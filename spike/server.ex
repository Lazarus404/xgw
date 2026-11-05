defmodule XGW.Spike.Server do
  @moduledoc """
  Browser spike GenServer: one Listener + Peer, SDP answer, trickle ICE, status.

  Started by `mix xgw.spike`; HTTP routes call `answer/2` and candidate helpers.
  """
  use GenServer

  require Logger

  alias XGW.{Listener, Peer, Spike.SDP}

  @ice_chars ~c"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

  @doc """
  Starts the named spike server. Opts are forwarded to `XGW.Listener.start_link/1`
  plus `:ice_tcp_only` for TCP-only answer candidates.
  """
  @spec start_link(keyword()) :: GenServer.on_start()
  def start_link(opts) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Builds and applies a local answer for `offer`, returning the SDP answer string.
  """
  @spec answer(binary(), keyword()) :: binary() | {:error, term()}
  def answer(offer, opts \\ []) when is_binary(offer) and is_list(opts) do
    GenServer.call(__MODULE__, {:answer, offer, opts})
  end

  @doc """
  Returns a map of spike counters (ICE/DTLS/RTP/SCTP, transport, candidates).
  """
  @spec status() :: map()
  def status, do: GenServer.call(__MODULE__, :status)

  @doc """
  Trickles a remote ICE candidate into the Peer (`candidate` / `sdpMid` map).
  """
  @spec add_remote_candidate(map()) :: :ok | {:error, term()}
  def add_remote_candidate(params) when is_map(params) do
    GenServer.call(__MODULE__, {:add_remote_candidate, params})
  end

  @doc """
  Local candidate lines gathered since index `since` (trickle poll).
  """
  @spec local_candidates_since(non_neg_integer()) :: {[String.t()], non_neg_integer()}
  def local_candidates_since(since) when is_integer(since) and since >= 0 do
    GenServer.call(__MODULE__, {:local_candidates_since, since})
  end

  @impl true
  def init(opts) do
    port = Keyword.get(opts, :port, 10_000)
    cert_dir = Keyword.get(opts, :cert_dir, Path.join(System.tmp_dir!(), "xgw-spike-certs"))
    advert_ips = advert_ips(opts)

    listener_opts =
      [
        ip: {0, 0, 0, 0},
        port: port,
        cert_dir: cert_dir,
        advertised_ips: advert_ips,
        include_loopback: true,
        stun_servers: Keyword.get(opts, :stun_servers, []),
        turn_servers: Keyword.get(opts, :turn_servers, []),
        turn_username: Keyword.get(opts, :turn_username),
        turn_password: Keyword.get(opts, :turn_password),
        turn_realm: Keyword.get(opts, :turn_realm),
        turn_secret: Keyword.get(opts, :turn_secret),
        turn_user_id: Keyword.get(opts, :turn_user_id),
        turn_ttl_s: Keyword.get(opts, :turn_ttl_s),
        relay_only: Keyword.get(opts, :relay_only, false),
        ice_tcp_enabled: Keyword.get(opts, :ice_tcp_enabled, false) or
          Keyword.get(opts, :ice_tcp_only, false)
      ]
      |> Enum.reject(fn {_k, v} -> v in [nil, []] end)

    with {:ok, listener} <- Listener.start_link(listener_opts),
         {:ok, peer} <-
           Peer.start_supervised(handler: self(), listener: listener, ice_lite: false) do
      fingerprint = Listener.local_fingerprint(listener)
      bound_port = Listener.port(listener)
      ice_tcp_only? = Keyword.get(opts, :ice_tcp_only, false)

      Logger.info(
        "xgw spike UDP port=#{bound_port} candidates=#{format_candidates(advert_ips, bound_port)}" <>
          if(ice_tcp_only?, do: " ice_tcp_only=true", else: "")
      )

      {:ok,
       %{
         listener: listener,
         peer: peer,
         fingerprint: fingerprint,
         advert_ips: advert_ips,
         ice_tcp_only?: ice_tcp_only?,
         ice_ufrag: nil,
         ice_pwd: nil,
         peer_endpoint: nil,
         trickle_lines: [],
         remote_trickle_count: 0,
         dtls: false,
         rtp_logged?: false,
         sctp: false,
         dc_echoed?: false
       }}
    end
  end

  @impl true
  def terminate(_reason, state) do
    if peer = state[:peer], do: close_spike_peer(peer)
    if listener = state[:listener], do: stop_spike_listener(listener)
    :ok
  end

  @impl true
  def handle_call({:answer, offer, opts}, _from, state) when is_list(opts) do
    ice_ufrag = random_ice_string(4)
    ice_pwd = random_ice_string(22)

    {remote_ufrag, _} = SDP.parse_ice(offer)

    if is_nil(remote_ufrag) do
      Logger.warning("xgw spike offer missing ice-ufrag")
    else
      Logger.info("xgw spike remote ice-ufrag=#{remote_ufrag}")
    end

    codec = SDP.normalize_codec(Keyword.get(opts, :codec, :opus))

    case answer_candidate_lines(state) do
      {:error, reason} ->
        Logger.error("xgw spike relay gather failed: #{inspect(reason)}")
        {:reply, {:error, reason}, state}

      {:ok, candidate_lines} ->
        answer =
          SDP.answer(offer,
            ice_ufrag: ice_ufrag,
            ice_pwd: ice_pwd,
            fingerprint: state.fingerprint,
            ip: hd(state.advert_ips),
            ips: state.advert_ips,
            port: Listener.port(state.listener),
            candidate_lines: candidate_lines,
            codec: codec
          )

        case Peer.apply_descriptions(state.peer, offer, answer) do
          :ok ->
            {:reply, answer,
             %{
               state
               | ice_ufrag: ice_ufrag,
                 ice_pwd: ice_pwd,
                 peer_endpoint: nil,
                 trickle_lines: [],
                 remote_trickle_count: 0,
                 dtls: false,
                 rtp_logged?: false,
                 sctp: false,
                 dc_echoed?: false
             }}

          {:error, reason} ->
            Logger.error("xgw spike apply_descriptions failed: #{inspect(reason)}")
            {:reply, {:error, reason}, state}
        end
    end
  end

  def handle_call({:answer, offer}, from, state) do
    handle_call({:answer, offer, []}, from, state)
  end

  def handle_call(:status, _from, state) do
    {:reply,
     %{
       peer: state.peer_endpoint,
       dtls: state.dtls,
       rtp_logged?: state.rtp_logged?,
       sctp: Map.get(state, :sctp, false),
       dc_echoed?: Map.get(state, :dc_echoed?, false),
       trickle: state.trickle_lines,
       remote_trickle: state.remote_trickle_count
     }, state}
  end

  def handle_call({:add_remote_candidate, params}, _from, state) do
    case Peer.add_remote_candidate(state.peer, params) do
      :ok ->
        {:reply, :ok, %{state | remote_trickle_count: state.remote_trickle_count + 1}}

      {:error, _} = err ->
        {:reply, err, state}
    end
  end

  def handle_call({:local_candidates_since, since}, _from, state) do
    lines = Enum.drop(state.trickle_lines, since)

    {:reply,
     %{
       candidates: lines,
       next: length(state.trickle_lines)
     }, state}
  end

  def handle_call(:sockname, _from, state) do
    {:reply, Listener.sockname(state.listener), state}
  end

  @impl true
  def handle_info({:xgw, :ice_connected, peer}, state) do
    endpoint = selected_endpoint(peer)
    transport = selected_transport(peer)
    Logger.info("xgw spike ICE connected peer=#{format_peer(endpoint)} transport=#{transport}")
    {:noreply, %{state | peer_endpoint: endpoint}}
  end

  def handle_info({:xgw, :dtls_connected, _peer}, state) do
    Logger.info("xgw spike DTLS handshake complete")
    {:noreply, %{state | dtls: true}}
  end

  def handle_info({:xgw, :sctp_connected, _peer}, state) do
    Logger.info("xgw spike SCTP association connected")
    {:noreply, %{state | sctp: true}}
  end

  def handle_info({:xgw, :datachannel, _peer, %{ref: ref, label: label, id: id}}, state) do
    Logger.info("xgw spike DataChannel open label=#{label} id=#{id} ref=#{inspect(ref)}")
    {:noreply, state}
  end

  def handle_info({:xgw, :datachannel_message, peer, ref, data}, state) do
    unless state.dc_echoed? do
      Logger.info("xgw spike SCTP ok channel=#{inspect(ref)} bytes=#{byte_size(data)}")
    end

    _ = Peer.send_datachannel(peer, ref, data)
    {:noreply, %{state | dc_echoed?: true, sctp: true}}
  end

  def handle_info({:xgw, :rtp, _peer, rtp, _meta}, state) do
    unless state.rtp_logged? do
      Logger.info(
        "xgw spike SRTP ok ssrc=#{rtp.ssrc} pt=#{rtp.payload_type} payload=#{byte_size(rtp.payload)}"
      )
    end

    {:noreply, %{state | rtp_logged?: true}}
  end

  def handle_info({:xgw, :local_candidate, _peer, %{candidate: line}}, state) do
    Logger.info("xgw spike trickle local #{line}")
    {:noreply, %{state | trickle_lines: state.trickle_lines ++ [line]}}
  end

  def handle_info({:xgw, :local_candidates_complete, _peer}, state) do
    Logger.debug("xgw spike local candidates complete")
    {:noreply, state}
  end

  def handle_info({:xgw, :closed, _peer, reason}, state) do
    Logger.warning("xgw spike peer closed: #{inspect(reason)}")
    {:noreply, %{state | peer_endpoint: nil, dtls: false}}
  end

  def handle_info(msg, state) do
    Logger.debug("xgw spike ignored: #{inspect(msg)}")
    {:noreply, state}
  end

  defp selected_endpoint(peer) do
    case :sys.get_state(peer) do
      %{selected: {ip, port}} -> {ip, port}
      _ -> nil
    end
  end

  defp selected_transport(peer) do
    case :sys.get_state(peer) do
      %{selected_transport: t} when not is_nil(t) -> t
      _ -> :unknown
    end
  end

  defp answer_candidate_lines(%{listener: listener, peer: peer} = state) do
    cond do
      Listener.relay_only?(listener) ->
        case Peer.prefetch_relay_candidates(peer) do
          {:ok, lines} ->
            Logger.info("xgw spike relay-only answer candidates=#{length(lines)}")
            {:ok, lines}

          {:error, reason} ->
            {:error, reason}
        end

      Map.get(state, :ice_tcp_only?, false) ->
        lines = Listener.tcp_candidate_lines(listener)

        if lines == [] do
          {:error, :no_tcp_candidates}
        else
          Logger.info("xgw spike ice-tcp-only answer candidates=#{length(lines)}")
          {:ok, lines}
        end

      true ->
        {:ok, Listener.host_candidate_lines(listener)}
    end
  end

  defp random_ice_string(n) do
    len = length(@ice_chars)

    for <<b <- :crypto.strong_rand_bytes(n)>>, into: <<>> do
      <<Enum.at(@ice_chars, rem(b, len))>>
    end
  end

  defp advert_ips(opts) do
    case Keyword.get(opts, :advert_ip) do
      nil -> SDP.detect_advert_ips()
      ip when is_tuple(ip) -> [ip]
    end
  end

  defp format_candidates(ips, port) do
    ips |> Enum.map_join(", ", &"#{format_ip(&1)}:#{port}")
  end

  defp format_ip(ip), do: ip |> :inet.ntoa() |> to_string()

  defp format_peer({ip, port}), do: "#{format_ip(ip)}:#{port}"
  defp format_peer(nil), do: "-"

  defp close_spike_peer(peer) when is_pid(peer) do
    if Process.alive?(peer) do
      try do
        Peer.close(peer)
      catch
        :exit, _ -> :ok
      end
    end
  end

  defp stop_spike_listener(listener) when is_pid(listener) do
    if Process.alive?(listener) do
      try do
        GenServer.stop(listener, :normal, 5_000)
      catch
        :exit, _ -> :ok
      end
    end
  end
end
