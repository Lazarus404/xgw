defmodule Mix.Tasks.Xgw.Spike do
  @moduledoc """
  Lab Mix task: run a browser-facing DTLS-SRTP spike against a local XGW stack.

  ## What this is for

  Manual proof that ICE, DTLS, and SRTP work end-to-end with Chrome. Not a
  production entrypoint -- use it when debugging the media gateway path.

      mix xgw.spike --port 10000 --http-port 8080

  Relay-only (colocated TURN on 127.0.0.1:3478):

      mix xgw.spike --port 10000 --http-port 8080 --relay-only

  Defaults TURN URI `turn:127.0.0.1:3478` with username/password `xgw`/`xgwpass`
  and realm `xirsys.com` (override via env `XGW_SPIKE_TURN_*` if needed).

  Open http://127.0.0.1:8080/ in Chrome. Default page is transceiver-only (no
  mic permission). Append `?mic=1` for live Opus SRTP proof. Hard-refresh after
  each restart. Requires `XTURN_LOCAL_DEPS=1` and a local
  [xmedialib](https://github.com/Lazarus404/xmedialib) checkout with the SRTP
  HMAC fix.

  ICE-TCP lab (TCP candidates only; forces TCP path without host firewall):

      mix xgw.spike --port 10000 --http-port 8080 --ice-tcp --ice-tcp-only

  ## RFCs

  Exercises the same stack as `XGW`: RFC 8445 (ICE), RFC 5764 (DTLS-SRTP),
  RFC 3711 (SRTP), optionally RFC 8656 (TURN relay-only) and RFC 6544 (ICE-TCP).
  """
  use Mix.Task

  @shortdoc "Run DTLS-SRTP browser spike"

  @impl Mix.Task
  def run(args) do
    System.put_env("XGW_SPIKE", "1")
    Mix.Task.run("compile")

    {opts, _} =
      OptionParser.parse!(args,
        strict: [
          port: :integer,
          http_port: :integer,
          advert_ip: :string,
          relay_only: :boolean,
          ice_tcp: :boolean,
          ice_tcp_only: :boolean
        ],
        aliases: [p: :port, h: :http_port]
      )

    Mix.Task.run("app.start")
    verify_xmedialib_srtp!()

    udp_port = Keyword.get(opts, :port, 10_000)
    http_port = Keyword.get(opts, :http_port, 8080)
    advert_ip = parse_advert_ip(Keyword.get(opts, :advert_ip))
    ice_tcp_only? = Keyword.get(opts, :ice_tcp_only, false)
    ice_tcp? = Keyword.get(opts, :ice_tcp, false) or ice_tcp_only?

    server_opts = [port: udp_port]
    server_opts = if advert_ip, do: Keyword.put(server_opts, :advert_ip, advert_ip), else: server_opts
    server_opts = if ice_tcp?, do: Keyword.put(server_opts, :ice_tcp_enabled, true), else: server_opts
    server_opts = if ice_tcp_only?, do: Keyword.put(server_opts, :ice_tcp_only, true), else: server_opts
    server_opts = maybe_relay_only(server_opts, opts)

    spike_server = Module.concat([XGW, Spike, Server])
    spike_http = Module.concat([XGW, Spike, HTTP])

    unless Code.ensure_loaded?(spike_server) and Code.ensure_loaded?(spike_http) do
      Mix.raise("spike modules missing; re-run with XGW_SPIKE=1 (mix task sets this)")
    end

    case apply(spike_server, :start_link, [server_opts]) do
      {:ok, server} ->
        advert_ips = :sys.get_state(server).advert_ips
        start_http(spike_http, udp_port, http_port, advert_ips, ice_tcp_only?)

      {:error, {:already_started, _}} ->
        Mix.raise("XGW.Spike.Server already running in this BEAM node")

      {:error, {:shutdown, {:failed_to_start, _, {:port_in_use, ^udp_port}}}} ->
        port_in_use!(udp_port)

      {:error, {:shutdown, {:failed_to_start, _, :eaddrinuse}}} ->
        port_in_use!(udp_port)

      {:error, reason} ->
        Mix.raise("failed to start spike server: #{inspect(reason)}")
    end
  end

  defp start_http(spike_http, udp_port, http_port, advert_ips, ice_tcp_only?) do
    {:ok, _} =
      apply(Bandit, :start_link, [
        [plug: spike_http, scheme: :http, ip: {0, 0, 0, 0}, port: http_port]
      ])

    candidates =
      advert_ips
      |> Enum.map_join("\n      ", fn ip ->
        "#{ip |> :inet.ntoa() |> to_string()}:#{udp_port}"
      end)

    media =
      if ice_tcp_only? do
        "TCP-only answer (UDP host candidates omitted)\n      TCP   #{candidates}"
      else
        "UDP   #{candidates}"
      end

    IO.puts("""
    xgw spike running
      HTTP  http://127.0.0.1:#{http_port}/
      #{media}
    Do not use the router (.1) unless the spike runs there.
    With XTURN_LOCAL_DEPS=1, xmedialib loads from your local checkout (run mix deps.get after SRTP changes).
    Hard-refresh the browser (Cmd+Shift+R) after each spike restart.
    Press Ctrl+C to stop.
    """)

    Process.sleep(:infinity)
  end

  defp parse_advert_ip(nil), do: nil

  defp parse_advert_ip(ip) do
    case :inet.parse_address(String.to_charlist(ip)) do
      {:ok, tuple} -> tuple
      _ -> raise "invalid --advert-ip #{inspect(ip)}"
    end
  end

  defp maybe_relay_only(server_opts, opts) do
    if Keyword.get(opts, :relay_only) do
      server_opts
      |> Keyword.put(:relay_only, true)
      |> Keyword.put(:turn_servers, [
        System.get_env("XGW_SPIKE_TURN_URI") || "turn:127.0.0.1:3478"
      ])
      |> Keyword.put(:turn_username, System.get_env("XGW_SPIKE_TURN_USER") || "xgw")
      |> Keyword.put(:turn_password, System.get_env("XGW_SPIKE_TURN_PASS") || "xgwpass")
      |> Keyword.put(:turn_realm, System.get_env("XGW_SPIKE_TURN_REALM") || "xirsys.com")
    else
      server_opts
    end
  end

  defp verify_xmedialib_srtp! do
    alias XMediaLib.{Rtp, Srtp}

    unless System.get_env("XTURN_LOCAL_DEPS") == "1" do
      Mix.raise("""
      Set so xgw uses a local xmedialib checkout with the SRTP HMAC fix
      (https://github.com/Lazarus404/xmedialib).

        mix deps.get
        mix xgw.spike --port 10000 --http-port 8080
      """)
    end

    ctx =
      Srtp.new_ctx(1, :aes_cm, :hmac_sha1, :crypto.strong_rand_bytes(16), :crypto.strong_rand_bytes(14), 10)

    if byte_size(ctx.k_a) != 20 do
      Mix.raise("""
      xmedialib SRTP auth key is #{byte_size(ctx.k_a)} bytes (WebRTC needs 20).

        mix deps.get
        mix compile --force
        mix xgw.spike --port 10000 --http-port 8080
      """)
    end

    rtp = %Rtp{
      padding: 0,
      marker: 0,
      payload_type: 111,
      sequence_number: 1,
      timestamp: 2,
      ssrc: 1,
      csrcs: [],
      extension: nil,
      payload: <<1, 2, 3>>
    }

    {:ok, enc, ctx2} = Srtp.encrypt(rtp, ctx)
    {:ok, dec, _} = Srtp.decrypt(enc, ctx2)

    unless dec.payload == rtp.payload do
      Mix.raise(
        "xmedialib SRTP round trip failed; see https://github.com/Lazarus404/xmedialib lib/srtp.ex"
      )
    end
  end

  defp port_in_use!(port) do
    hint =
      case System.cmd("lsof", ["-nP", "-iUDP:#{port}"], stderr_to_stdout: true) do
        {out, 0} when out != "" -> "\n\nCurrently bound:\n#{String.trim(out)}"
        _ -> ""
      end

    Mix.raise("""
    UDP port #{port} is already in use.

    Stop the other spike (Ctrl+C in its terminal) or pick another port:
      mix xgw.spike --port #{port + 1} --http-port 8080#{hint}
    """)
  end
end
