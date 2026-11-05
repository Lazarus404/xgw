defmodule XGW.Listener do
  @moduledoc """
  Shared UDP (and optional TCP) socket that receives all WebRTC traffic for
  many peers and routes each packet to the right `XGW.Peer`.

  ## Why a shared listener

  Opening one UDP port per browser would not scale and would break demux
  assumptions. One Listener binds the media port; inbound bytes are classified
  (`XGW.Demux`) and dispatched:

  * **STUN Binding** -- look up the Peer by local ICE ufrag in USERNAME
    (`local:remote` at this host)
  * **RTP / RTCP / DTLS** -- look up by remote `{ip, port}` after `bind_remote/3`
  * **TURN ChannelData** -- look up by channel number from `bind_turn_channel/3`
  * **TURN Data Indication** -- unwrap, then re-demux the inner packet

  With a single registered Peer and no bind keys, all classified packets go to
  that Peer (Echo / one-Peer-per-Listener back-compat).

  Inbound media meta includes `:arrival_us` (monotonic microseconds) stamped in
  `route_packet/4` before `Peer.deliver/4`, so TWCC arrivals exclude Peer
  mailbox delay.

  ## Gather options (on `start_link/1`)

  * Host: `:advertised_ip`, `:advertised_ips`, `:include_loopback` (default `true`)
  * srflx: `:stun_servers` (default `[]`), `:gather_timeout_ms` (default `3000`)
  * relay: `:turn_servers` plus TURN credential opts
  * `:relay_only` -- skip host/srflx SDP validation when the answer is relay-only
  * ICE-TCP: `:ice_tcp_enabled` / `:ice_tcp_port` for passive TCP candidates

  Call `gather_candidates/2` before publishing answer SDP when you need host +
  srflx + relay lines embedded up front.

  ## RFCs

  * RFC 7983 -- demux of STUN / DTLS / TURN ChannelData / RTP/RTCP on one socket
  * RFC 8445 -- ICE candidate gather and STUN Binding dispatch by ufrag
  * RFC 8656 -- TURN Data Indication unwrap and ChannelData
  * RFC 6544 -- optional ICE-TCP passive candidates and accept path
  """

  use GenServer

  require Logger

  alias XGW.{Certs, Demux, DTLS, DTLS.Transport, ICE, ICE.Gather, Listener.TCP, Peer}
  alias XGW.Peer.Turn
  alias XMediaLib.SDP.Candidate
  alias XMediaLib.Stun

  @doc """
  Starts a UDP listener on `ip` / `port` (use `port: 0` for an ephemeral bind).

  Optional gather opts: `:advertised_ip`, `:advertised_ips`, `:include_loopback`,
  `:stun_servers`, `:gather_timeout_ms`, `:turn_servers`, `:relay_only`, TURN
  credential opts, `:ice_tcp_enabled`, `:ice_tcp_port`.
  """
  @spec start_link(keyword()) :: {:ok, pid()} | {:error, term()}
  def start_link(opts) when is_list(opts) do
    GenServer.start_link(__MODULE__, opts, [])
  end

  @doc """
  Bound port of the shared UDP socket.
  """
  @spec port(pid()) :: :inet.port_number()
  def port(listener), do: GenServer.call(listener, :port)

  @doc """
  Registers `peer_pid` for demux (monitor only until bind_* keys are set).
  """
  @spec register_peer(pid(), pid()) :: :ok
  def register_peer(listener, peer_pid) do
    GenServer.call(listener, {:register_peer, peer_pid})
  end

  @doc """
  Maps local ICE ufrag to `peer_pid` for STUN Binding demux.
  """
  @spec bind_ufrag(pid(), pid(), String.t()) :: :ok
  def bind_ufrag(listener, peer_pid, local_ufrag)
      when is_binary(local_ufrag) and local_ufrag != "" do
    GenServer.call(listener, {:bind_ufrag, peer_pid, local_ufrag})
  end

  @doc """
  Maps remote `{ip, port}` to `peer_pid` for RTP/RTCP/DTLS demux.
  """
  @spec bind_remote(pid(), pid(), {:inet.ip_address(), :inet.port_number()}) :: :ok
  def bind_remote(listener, peer_pid, {ip, port} = from)
      when is_tuple(ip) and is_integer(port) do
    GenServer.call(listener, {:bind_remote, peer_pid, from})
  end

  @doc """
  Allocates the next TURN channel number unique on this Listener socket.
  """
  @spec allocate_turn_channel(pid(), pid()) :: {:ok, non_neg_integer()}
  def allocate_turn_channel(listener, peer_pid) do
    GenServer.call(listener, {:allocate_turn_channel, peer_pid})
  end

  @doc """
  Maps TURN ChannelData `channel` to `peer_pid`.
  """
  @spec bind_turn_channel(pid(), pid(), non_neg_integer()) :: :ok
  def bind_turn_channel(listener, peer_pid, channel)
      when is_integer(channel) and channel >= 0x4000 and channel <= 0x7FFF do
    GenServer.call(listener, {:bind_turn_channel, peer_pid, channel})
  end

  @doc """
  Removes `peer_pid` and all demux keys that pointed at it.
  """
  @spec unregister_peer(pid(), pid()) :: :ok
  def unregister_peer(listener, peer_pid) do
    GenServer.call(listener, {:unregister_peer, peer_pid})
  end

  @doc """
  Sends a UDP datagram on the listener socket (STUN replies, etc.).
  """
  @spec send(pid(), :inet.ip_address(), :inet.port_number(), binary()) :: :ok
  def send(listener, ip, port, data) do
    GenServer.cast(listener, {:send, ip, port, data})
  end

  @doc """
  Sends a UDP datagram and waits for `:gen_udp.send/4` result (outbound media).
  """
  @spec send_datagram(pid(), :inet.ip_address(), :inet.port_number(), binary()) ::
          :ok | {:error, term()}
  def send_datagram(listener, ip, port, data) do
    GenServer.call(listener, {:send_datagram, ip, port, data})
  end

  @doc """
  SHA-256 fingerprint of the listener DTLS certificate (SDP format).
  """
  @spec local_fingerprint(pid()) :: String.t()
  def local_fingerprint(listener), do: GenServer.call(listener, :local_fingerprint)

  @doc """
  Returns the shared UDP socket used for STUN/RTP and DTLS `cb_info`.
  """
  @spec udp_sock(pid()) :: port()
  def udp_sock(listener), do: GenServer.call(listener, :udp_sock)

  @doc """
  Returns the SSL listen socket for DTLS accept (shared UDP via Transport).
  """
  @spec listen_sock(pid()) :: :ssl.sslsocket()
  def listen_sock(listener), do: GenServer.call(listener, :listen_sock)

  @doc """
  Bound socket `{ip, port}`.
  """
  @spec sockname(pid()) :: {:inet.ip_address(), :inet.port_number()}
  def sockname(listener), do: GenServer.call(listener, :sockname)

  @doc """
  Host gather options configured at listener start.
  """
  @spec gather_opts(pid()) :: keyword()
  def gather_opts(listener), do: GenServer.call(listener, :gather_opts)

  @doc """
  Host ICE candidate with highest priority for the listener UDP socket.
  """
  @spec host_candidate(pid()) :: Candidate.t()
  def host_candidate(listener) do
    case host_candidates(listener) do
      [c | _] -> c
      [] -> raise ArgumentError, "no host addresses resolved for listener gather"
    end
  end

  @doc """
  All host ICE candidates for the listener UDP socket (multi-interface).
  """
  @spec host_candidates(pid()) :: [Candidate.t()]
  def host_candidates(listener), do: GenServer.call(listener, :host_candidates)

  @doc """
  SDP `a=candidate:` attribute value (without prefix) for the highest-priority host.
  """
  @spec host_candidate_line(pid()) :: String.t()
  def host_candidate_line(listener) do
    listener |> host_candidate() |> ICE.candidate_line()
  end

  @doc """
  SDP `a=candidate:` lines for all gathered host candidates (without prefix).
  """
  @spec host_candidate_lines(pid()) :: [String.t()]
  def host_candidate_lines(listener) do
    lines = Enum.map(host_candidates(listener), &ICE.candidate_line/1)

    if ice_tcp_enabled?(listener) do
      lines ++ tcp_candidate_lines(listener)
    else
      lines
    end
  end

  @doc """
  Returns true when ICE-TCP passive candidates are enabled.
  """
  @spec ice_tcp_enabled?(pid()) :: boolean()
  def ice_tcp_enabled?(listener), do: GenServer.call(listener, :ice_tcp_enabled?)

  @doc """
  SDP `a=candidate:` lines for passive TCP host candidates.
  """
  @spec tcp_candidate_lines(pid()) :: [String.t()]
  def tcp_candidate_lines(listener) do
    Enum.map(tcp_candidates(listener), &ICE.candidate_line/1)
  end

  @doc """
  Passive ICE-TCP host candidates (empty when ICE-TCP is disabled).
  """
  @spec tcp_candidates(pid()) :: [Candidate.t()]
  def tcp_candidates(listener), do: GenServer.call(listener, :tcp_candidates)

  @doc """
  Sends a framed STUN message over an established ICE-TCP connection to `peer_addr`.
  """
  @spec send_tcp_stun(pid(), ICE.endpoint(), binary()) :: :ok | {:error, term()}
  def send_tcp_stun(listener, peer_addr, wire) do
    GenServer.call(listener, {:send_tcp_stun, peer_addr, wire})
  end

  @doc """
  Returns the bound ICE-TCP listen port when enabled, else `nil`.
  """
  @spec tcp_port(pid()) :: :inet.port_number() | nil
  def tcp_port(listener), do: GenServer.call(listener, :tcp_port)

  @doc """
  Returns `{certfile, keyfile}` paths for DTLS handshakes.
  """
  @spec cert_paths(pid()) :: {String.t(), String.t()}
  def cert_paths(listener), do: GenServer.call(listener, :cert_paths)

  @doc """
  Connects to `peer_addr` over TCP if needed and sends a framed STUN message.
  """
  @spec tcp_connect_stun(pid(), ICE.endpoint(), binary()) :: :ok | {:error, term()}
  def tcp_connect_stun(listener, peer_addr, wire) do
    GenServer.call(listener, {:tcp_connect_stun, peer_addr, wire})
  end

  @doc """
  Configured STUN server URIs for srflx gather.
  """
  @spec stun_servers(pid()) :: [String.t()]
  def stun_servers(listener), do: GenServer.call(listener, :stun_servers)

  @doc """
  Pre-answer srflx gather timeout in milliseconds.
  """
  @spec gather_timeout_ms(pid()) :: non_neg_integer()
  def gather_timeout_ms(listener), do: GenServer.call(listener, :gather_timeout_ms)

  @doc """
  Gathers host, srflx, and relay candidates within `timeout_ms`.

  Returns `%{host: [...], srflx: [...], relay: [...]}`.
  """
  @spec gather_candidates(pid(), keyword()) :: %{
          host: [Candidate.t()],
          srflx: [Candidate.t()],
          relay: [Candidate.t()]
        }
  def gather_candidates(listener, opts \\ []) do
    timeout_ms = Keyword.get(opts, :timeout_ms, gather_timeout_ms(listener))
    sockname = sockname(listener)
    gather_opts = gather_opts(listener)
    stun_servers = stun_servers(listener)
    turn_servers = turn_servers(listener)
    turn_credentials = turn_credentials(listener)

    send_recv = fn wire, {ip, port} ->
      turn_request(listener, ip, port, timeout_ms, wire)
    end

    Gather.gather_with_timeout(
      sockname,
      Keyword.merge(gather_opts,
        stun_servers: stun_servers,
        turn_servers: turn_servers,
        turn_credentials: turn_credentials,
        gather_timeout_ms: timeout_ms,
        send_recv: send_recv
      )
    )
  end

  @doc """
  Configured TURN server URIs for relay gather.
  """
  @spec turn_servers(pid()) :: [String.t()]
  def turn_servers(listener), do: GenServer.call(listener, :turn_servers)

  @doc """
  When true, answer SDP may omit host/srflx locals (relay-only / zero-public-port).
  """
  @spec relay_only?(pid()) :: boolean()
  def relay_only?(listener), do: GenServer.call(listener, :relay_only?)

  @doc """
  TURN credential options for relay gather.
  """
  @spec turn_credentials(pid()) :: keyword()
  def turn_credentials(listener), do: GenServer.call(listener, :turn_credentials)

  @doc """
  SDP `a=candidate:` lines for relay candidates gathered within the timeout.
  """
  @spec relay_candidate_lines(pid(), keyword()) :: [String.t()]
  def relay_candidate_lines(listener, opts \\ []) do
    listener
    |> gather_candidates(opts)
    |> Map.fetch!(:relay)
    |> Enum.map(&ICE.candidate_line/1)
  end

  @doc """
  Sends a STUN/TURN request on the listener socket and waits for a response.
  """
  @spec turn_request(
          pid(),
          :inet.ip_address(),
          :inet.port_number(),
          non_neg_integer(),
          binary()
        ) :: {:ok, binary()} | {:error, term()}
  def turn_request(listener, ip, port, timeout_ms, wire) do
    GenServer.call(listener, {:turn_request, ip, port, timeout_ms, wire})
  end

  @doc """
  Sends a STUN Binding request on the listener socket and waits for a response.

  Optional fifth argument is pre-encoded request wire (defaults to plain Binding).
  """
  @spec stun_binding(
          pid(),
          :inet.ip_address(),
          :inet.port_number(),
          non_neg_integer(),
          binary() | nil
        ) :: {:ok, binary()} | {:error, term()}
  def stun_binding(listener, stun_ip, stun_port, timeout_ms, wire \\ nil) do
    turn_request(listener, stun_ip, stun_port, timeout_ms, wire || Gather.stun_binding_request())
  end

  @doc """
  SDP `a=candidate:` lines for srflx candidates gathered within the timeout.
  """
  @spec srflx_candidate_lines(pid(), keyword()) :: [String.t()]
  def srflx_candidate_lines(listener, opts \\ []) do
    listener
    |> gather_candidates(opts)
    |> Map.fetch!(:srflx)
    |> Enum.map(&ICE.candidate_line/1)
  end

  @impl true
  def init(opts) do
    ip = Keyword.get(opts, :ip, {0, 0, 0, 0})
    port = Keyword.get(opts, :port, 0)
    cert_dir = Keyword.get(opts, :cert_dir, Path.join(System.tmp_dir!(), "xgw-certs"))
    {certfile, keyfile} = Certs.ensure!(cert_dir)

    gather_opts =
      [
        advertised_ip: Keyword.get(opts, :advertised_ip),
        advertised_ips: Keyword.get(opts, :advertised_ips),
        include_loopback: Keyword.get(opts, :include_loopback, true)
      ]
      |> Enum.reject(fn {_k, v} -> is_nil(v) end)

    stun_servers = Keyword.get(opts, :stun_servers, [])
    gather_timeout_ms = Keyword.get(opts, :gather_timeout_ms, 3_000)
    turn_servers = Keyword.get(opts, :turn_servers, [])
    relay_only = Keyword.get(opts, :relay_only, false)
    ice_tcp_enabled = Keyword.get(opts, :ice_tcp_enabled, false)
    ice_tcp_port = Keyword.get(opts, :ice_tcp_port, port)

    turn_credentials =
      [
        turn_username: Keyword.get(opts, :turn_username),
        turn_password: Keyword.get(opts, :turn_password),
        turn_realm: Keyword.get(opts, :turn_realm),
        turn_secret: Keyword.get(opts, :turn_secret),
        turn_user_id: Keyword.get(opts, :turn_user_id),
        turn_ttl_s: Keyword.get(opts, :turn_ttl_s)
      ]
      |> Enum.reject(fn {_k, v} -> is_nil(v) end)

    listener = self()
    Process.put({Transport, :listener}, listener)

    ssl_opts =
      DTLS.listen_opts(certfile: certfile, keyfile: keyfile, port: port)
      |> Keyword.put(:ip, ip)

    case :ssl.listen(port, ssl_opts) do
      {:ok, listen_sock} ->
        udp = Process.get({Transport, :socket})
        Process.delete({Transport, :listener})

        :ok = :gen_udp.controlling_process(udp, listener)
        :ok = :inet.setopts(udp, active: :once)
        {:ok, {bound_ip, bound_port}} = :inet.sockname(udp)

        {tcp_listen_sock, tcp_acceptor, tcp_port} =
          maybe_start_tcp({bound_ip, ice_tcp_port}, ice_tcp_enabled)

        {:ok,
         %{
           udp: udp,
           listen_sock: listen_sock,
           bound_ip: bound_ip,
           port: bound_port,
           certfile: certfile,
           keyfile: keyfile,
           gather_opts: gather_opts,
           stun_servers: stun_servers,
           turn_servers: turn_servers,
           turn_credentials: turn_credentials,
           relay_only: relay_only,
           ice_tcp_enabled: ice_tcp_enabled,
           ice_tcp_port: tcp_port,
           tcp_listen_sock: tcp_listen_sock,
           tcp_acceptor: tcp_acceptor,
           tcp_sockets: %{},
           gather_timeout_ms: gather_timeout_ms,
           peers: MapSet.new(),
           by_ufrag: %{},
           by_from: %{},
           by_turn_channel: %{},
           next_turn_channel: 0x4000,
           ssl_sock: nil
         }}

      {:error, :already_listening} ->
        {:stop, {:port_in_use, port}}

      {:error, :eaddrinuse} ->
        {:stop, {:port_in_use, port}}

      {:error, reason} ->
        {:stop, reason}
    end
  end

  @impl true
  def terminate(_reason, state) do
    DTLS.close(state.listen_sock, state.ssl_sock)
    if udp = state.udp, do: :gen_udp.close(udp)
    if udp = state.udp, do: :persistent_term.erase({Transport, udp})
    close_tcp_listener(state)
    :ok
  end

  defp shutdown_tcp_acceptor(nil), do: :ok

  defp shutdown_tcp_acceptor(%Task{} = task) do
    Process.exit(task.pid, :shutdown)
  end

  defp shutdown_tcp_acceptor(pid) when is_pid(pid) do
    Process.exit(pid, :shutdown)
  end

  defp maybe_start_tcp(_sockname, false), do: {nil, nil, nil}

  defp maybe_start_tcp({ip, port}, true) do
    case TCP.listen({ip, port}) do
      {:ok, listen_sock} ->
        listener = self()
        {:ok, task} = Task.start_link(fn -> TCP.start_acceptor(listener, listen_sock) end)
        {:ok, bound_port} = :inet.port(listen_sock)
        {listen_sock, task, bound_port}

      {:error, reason} ->
        Logger.warning("xgw ICE-TCP listen failed: #{inspect(reason)}")
        {nil, nil, nil}
    end
  end

  defp close_tcp_listener(%{tcp_listen_sock: sock, tcp_acceptor: acceptor}) when is_port(sock) do
    shutdown_tcp_acceptor(acceptor)
    :gen_tcp.close(sock)
  end

  defp close_tcp_listener(_), do: :ok

  @impl true
  def handle_call(:port, _from, state), do: {:reply, state.port, state}

  def handle_call(:sockname, _from, state) do
    {:reply, {state.bound_ip, state.port}, state}
  end

  def handle_call(:gather_opts, _from, state) do
    {:reply, state.gather_opts, state}
  end

  def handle_call(:stun_servers, _from, state) do
    {:reply, state.stun_servers, state}
  end

  def handle_call(:gather_timeout_ms, _from, state) do
    {:reply, state.gather_timeout_ms, state}
  end

  def handle_call(:turn_servers, _from, state) do
    {:reply, state.turn_servers, state}
  end

  def handle_call(:turn_credentials, _from, state) do
    {:reply, state.turn_credentials, state}
  end

  def handle_call(:relay_only?, _from, state) do
    {:reply, state.relay_only, state}
  end

  def handle_call(:ice_tcp_enabled?, _from, state) do
    {:reply, state.ice_tcp_enabled, state}
  end

  def handle_call(:tcp_port, _from, state) do
    {:reply, state.ice_tcp_port, state}
  end

  def handle_call(:tcp_candidates, _from, state) do
    if state.ice_tcp_enabled and state.ice_tcp_port do
      {:reply,
       Gather.tcp_passive_candidates({state.bound_ip, state.ice_tcp_port}, state.gather_opts),
       state}
    else
      {:reply, [], state}
    end
  end

  def handle_call({:send_tcp_stun, peer_addr, wire}, _from, state) do
    case Map.get(state.tcp_sockets, peer_addr) do
      sock when is_port(sock) ->
        {:reply, TCP.send_stun(sock, wire), state}

      _ ->
        {:reply, {:error, :no_tcp_connection}, state}
    end
  end

  def handle_call({:tcp_connect_stun, peer_addr, wire}, _from, state) do
    case Map.get(state.tcp_sockets, peer_addr) do
      sock when is_port(sock) ->
        {:reply, TCP.send_stun(sock, wire), state}

      _ ->
        do_tcp_connect_stun(state, peer_addr, wire)
    end
  end

  def handle_call(:cert_paths, _from, state) do
    {:reply, {state.certfile, state.keyfile}, state}
  end

  def handle_call(:host_candidates, _from, state) do
    {:reply, Gather.host_candidates({state.bound_ip, state.port}, state.gather_opts), state}
  end

  def handle_call(:listen_sock, _from, state) do
    {:reply, state.listen_sock, state}
  end

  def handle_call(:udp_sock, _from, state) do
    {:reply, state.udp, state}
  end

  def handle_call(:local_fingerprint, _from, state) do
    {:reply, Certs.fingerprint(state.certfile), state}
  end

  def handle_call({:register_peer, peer_pid}, _from, state) do
    _ = Process.monitor(peer_pid)
    {:reply, :ok, %{state | peers: MapSet.put(state.peers, peer_pid)}}
  end

  def handle_call({:bind_ufrag, peer_pid, local_ufrag}, _from, state) do
    by_ufrag =
      state.by_ufrag
      |> reject_peer_values(peer_pid)
      |> Map.put(local_ufrag, peer_pid)

    {:reply, :ok, %{state | by_ufrag: by_ufrag}}
  end

  def handle_call({:bind_remote, peer_pid, from}, _from, state) do
    {:reply, :ok, %{state | by_from: Map.put(state.by_from, from, peer_pid)}}
  end

  def handle_call({:allocate_turn_channel, peer_pid}, _from, state) do
    channel = state.next_turn_channel

    {:reply, {:ok, channel},
     %{
       state
       | next_turn_channel: channel + 1,
         peers: MapSet.put(state.peers, peer_pid)
     }}
  end

  def handle_call({:bind_turn_channel, peer_pid, channel}, _from, state) do
    {:reply, :ok, %{state | by_turn_channel: Map.put(state.by_turn_channel, channel, peer_pid)}}
  end

  def handle_call({:unregister_peer, peer_pid}, _from, state) do
    {:reply, :ok, drop_peer(state, peer_pid)}
  end

  def handle_call({:send_datagram, ip, port, data}, _from, state) do
    {:reply, :gen_udp.send(state.udp, ip, port, data), state}
  end

  def handle_call({:turn_request, ip, port, timeout_ms, wire}, _from, state) do
    udp = state.udp
    :inet.setopts(udp, active: false)

    result =
      case :gen_udp.send(udp, ip, port, wire) do
        :ok -> recv_turn_response(udp, wire, timeout_ms, state)
        err -> err
      end

    :inet.setopts(udp, active: :once)
    {:reply, result, state}
  end

  def handle_call({:stun_binding, stun_ip, stun_port, timeout_ms, wire}, from, state) do
    handle_call({:turn_request, stun_ip, stun_port, timeout_ms, wire}, from, state)
  end

  defp recv_turn_response(udp, request, timeout_ms, state) do
    deadline = System.monotonic_time(:millisecond) + timeout_ms
    expect_tid = stun_transaction_id(request)
    recv_turn_response_loop(udp, expect_tid, deadline, state)
  end

  defp recv_turn_response_loop(udp, expect_tid, deadline, state) do
    remaining = deadline - System.monotonic_time(:millisecond)

    if remaining <= 0 do
      {:error, :timeout}
    else
      case :gen_udp.recv(udp, 2048, max(remaining, 1)) do
        {:ok, {ip, port, data}} when is_binary(data) ->
          if expect_tid != :error and stun_transaction_id(data) == expect_tid do
            {:ok, data}
          else
            _ = route_packet(data, {ip, port}, state)
            recv_turn_response_loop(udp, expect_tid, deadline, state)
          end

        {:ok, data} when is_binary(data) ->
          if expect_tid != :error and stun_transaction_id(data) == expect_tid do
            {:ok, data}
          else
            _ = route_packet(data, {{0, 0, 0, 0}, 0}, state)
            recv_turn_response_loop(udp, expect_tid, deadline, state)
          end

        {:error, _} = err ->
          err
      end
    end
  end

  defp stun_transaction_id(<<_type::16, _len::16, _magic::32, tid::binary-size(12), _::binary>>),
    do: tid

  defp stun_transaction_id(_), do: :error

  @impl true
  def handle_cast({:send, ip, port, data}, state) do
    _ = :gen_udp.send(state.udp, ip, port, data)
    {:noreply, state}
  end

  def handle_cast({:inject_dtls, ip, port, data}, state) do
    Transport.inject(state.udp, ip, port, data)
    {:noreply, state}
  end

  @impl true
  def handle_info({:udp, udp, ip, port, data}, state) do
    state = route_packet(data, {ip, port}, state)
    :inet.setopts(udp, active: :once)
    {:noreply, state}
  end

  def handle_info({:udp_passive, udp}, state) do
    :inet.setopts(udp, active: :once)
    {:noreply, state}
  end

  def handle_info({:udp_error, _udp, reason}, state) do
    Logger.warning("xgw listener UDP error: #{inspect(reason)}")
    {:noreply, state}
  end

  def handle_info({:DOWN, _ref, :process, pid, _reason}, state) do
    if MapSet.member?(state.peers, pid) do
      {:noreply, drop_peer(state, pid)}
    else
      {:noreply, state}
    end
  end

  def handle_info({:xgw_internal, :tcp_accept, sock}, state) do
    case :inet.peername(sock) do
      {:ok, peer_addr} ->
        :inet.setopts(sock, [:binary, active: false, packet: :raw])
        listener = self()
        Task.start_link(fn -> tcp_read_loop(listener, sock, peer_addr) end)

        {:noreply, %{state | tcp_sockets: Map.put(state.tcp_sockets, peer_addr, sock)}}

      _ ->
        :gen_tcp.close(sock)
        {:noreply, state}
    end
  end

  def handle_info({:xgw_internal, :tcp_frame, peer_addr, data}, state) do
    tcp_sock = Map.get(state.tcp_sockets, peer_addr)
    meta = %{from: peer_addr, transport: :tcp, tcp_sock: tcp_sock}
    _ = route_packet(data, peer_addr, state, meta)
    {:noreply, state}
  end

  def handle_info({:xgw_internal, :tcp_closed, peer_addr}, state) do
    {:noreply, %{state | tcp_sockets: Map.delete(state.tcp_sockets, peer_addr)}}
  end

  def handle_info(_msg, state), do: {:noreply, state}

  defp tcp_read_loop(listener, sock, peer_addr) do
    case TCP.read_stun(sock, 30_000) do
      {:ok, data} ->
        send(listener, {:xgw_internal, :tcp_frame, peer_addr, data})
        tcp_read_loop(listener, sock, peer_addr)

      _ ->
        send(listener, {:xgw_internal, :tcp_closed, peer_addr})
        :gen_tcp.close(sock)
    end
  end

  defp do_tcp_connect_stun(state, peer_addr, wire) do
    listener = self()

    with {:ok, sock} <- XSockets.Transport.TCP.connect(elem(peer_addr, 0), elem(peer_addr, 1), []),
         :ok <- TCP.send_stun(sock, wire) do
      Task.start_link(fn -> tcp_read_loop(listener, sock, peer_addr) end)
      {:reply, :ok, %{state | tcp_sockets: Map.put(state.tcp_sockets, peer_addr, sock)}}
    else
      err -> {:reply, err, state}
    end
  end

  defp route_packet(data, peer_addr, state, meta \\ nil)

  defp route_packet(data, peer_addr, state, meta) do
    meta = stamp_arrival_meta(meta || %{from: peer_addr})

    case Demux.classify_kind(data) do
      {:ok, :stun} ->
        case Turn.unwrap_data_indication(data) do
          {:ok, inner, xor_peer} ->
            # Keep the outer wire stamp so TURN unwrap does not look like reordering.
            route_packet(inner, xor_peer, state, %{
              from: xor_peer,
              arrival_us: Map.get(meta, :arrival_us)
            })

          :not_turn_data ->
            deliver_to(resolve_stun_peer(data, state), :stun, data, meta)
            state
        end

      {:ok, :turn_channel} ->
        deliver_to(resolve_turn_channel_peer(data, state), :turn_channel, data, meta)
        state

      {:ok, kind} when kind in [:rtp, :rtcp] ->
        deliver_to(resolve_from_peer(peer_addr, state), kind, data, meta)
        state

      {:ok, :dtls} ->
        case resolve_from_peer(peer_addr, state) do
          peer when is_pid(peer) ->
            # Peer owns DTLS inject (buffer in ice_wait, Transport.inject when ready).
            deliver_to(peer, :dtls, data, meta)

          _ ->
            # No Peer demux hit: OTP accept path (lab handshake without Peer).
            Transport.inject(state.udp, elem(peer_addr, 0), elem(peer_addr, 1), data)
        end

        state

      {:ok, kind} ->
        deliver_to(single_peer_fallback(state), kind, data, meta)
        state

      _ ->
        state
    end
  end

  defp stamp_arrival_meta(meta) when is_map(meta) do
    if is_integer(Map.get(meta, :arrival_us)) do
      meta
    else
      Map.put(meta, :arrival_us, System.monotonic_time(:microsecond))
    end
  end

  defp resolve_stun_peer(data, state) do
    case peek_local_ufrag(data) do
      {:ok, ufrag} ->
        case Map.get(state.by_ufrag, ufrag) do
          pid when is_pid(pid) -> pid
          _ -> single_peer_fallback(state)
        end

      :error ->
        single_peer_fallback(state)
    end
  end

  defp resolve_from_peer(from, state) do
    case Map.get(state.by_from, from) do
      pid when is_pid(pid) -> pid
      _ -> single_peer_fallback(state)
    end
  end

  defp resolve_turn_channel_peer(<<channel::16, _::binary>>, state) do
    case Map.get(state.by_turn_channel, channel) do
      pid when is_pid(pid) -> pid
      _ -> single_peer_fallback(state)
    end
  end

  defp resolve_turn_channel_peer(_, state), do: single_peer_fallback(state)

  defp single_peer_fallback(state) do
    case MapSet.to_list(state.peers) do
      [only] -> only
      _ -> nil
    end
  end

  defp deliver_to(nil, _kind, _data, _meta), do: :ok

  defp deliver_to(peer, kind, data, meta) when is_pid(peer) do
    Peer.deliver(peer, kind, data, meta)
  end

  defp peek_local_ufrag(data) when is_binary(data) do
    case safe_stun_decode(data) do
      {:ok, %Stun{attrs: attrs}} ->
        case Map.get(attrs, :username) do
          username when is_binary(username) ->
            case String.split(username, ":", parts: 2) do
              [local, _] when local != "" -> {:ok, local}
              _ -> :error
            end

          _ ->
            :error
        end

      _ ->
        :error
    end
  end

  defp safe_stun_decode(data) do
    Stun.decode(data)
  rescue
    _ -> :error
  catch
    _, _ -> :error
  end

  defp drop_peer(state, peer_pid) do
    %{
      state
      | peers: MapSet.delete(state.peers, peer_pid),
        by_ufrag: reject_peer_values(state.by_ufrag, peer_pid),
        by_from: reject_peer_values(state.by_from, peer_pid),
        by_turn_channel: reject_peer_values(state.by_turn_channel, peer_pid)
    }
  end

  defp reject_peer_values(map, peer_pid) do
    map
    |> Enum.reject(fn {_k, v} -> v == peer_pid end)
    |> Map.new()
  end
end
