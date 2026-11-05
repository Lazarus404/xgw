defmodule XGW.DTLS.Transport do
  @moduledoc """
  Adapts OTP `:ssl` DTLS to XGW's shared Listener socket.

  ## Role in the stack

  Erlang's SSL application talks to the network through a small **callback
  info** (`cb_info`) module. This module is that adapter: inbound DTLS
  datagrams are **injected** into the connection owner after the Listener
  demuxes them, and outbound DTLS bytes go out through the same UDP (or
  ICE-TCP / TURN-wrapped) path the Peer already selected.

  Without this layer, OTP would open a second UDP port and break WebRTC's
  "one 5-tuple for STUN + DTLS + SRTP" model.

  ## RFCs

  * RFC 9147 / RFC 6347 -- DTLS datagram transport
  * RFC 7983 -- sharing one 5-tuple with STUN and SRTP
  * RFC 8656 -- TURN Send Indication / ChannelData when the selected path is relay
  * RFC 6544 -- ICE-TCP framing when the selected path is TCP
  """

  @typedoc "UDP socket used as the DTLS datagram transport (`:gen_udp` port)."
  @type socket :: port()

  @ignore_key {__MODULE__, :ignore_owners}

  @doc """
  Opens a UDP socket suitable for `:ssl` DTLS `cb_info` (binary, inactive).

  When the process dictionary has `{__MODULE__, :listener}`, registers the
  socket in `:persistent_term` for inject/send routing.
  """
  @spec open(:inet.port_number(), keyword()) :: {:ok, socket()} | {:error, term()}
  def open(port, opts) do
    inet_opts =
      opts
      |> Keyword.drop([:active, :mode, :packet, :packet_size])
      |> Keyword.merge(reuseaddr: true, active: false, mode: :binary, ip: {0, 0, 0, 0})

    case :gen_udp.open(port, inet_opts) do
      {:ok, sock} ->
        if listener = Process.get({__MODULE__, :listener}) do
          :persistent_term.put({__MODULE__, sock}, %{listener: listener, owner: nil, pending: []})
          Process.put({__MODULE__, :socket}, sock)
        end

        {:ok, sock}

      {:error, _} = error ->
        error
    end
  end

  @doc """
  Marks `pid` so later `controlling_process/2` calls do not make it the DTLS UDP owner.

  Used before `:ssl.controlling_process(ssl_sock, peer)` so Peer receives `{:ssl, ...}`
  without stealing post-handshake DTLS injects needed for SCTP.
  """
  @spec ignore_owner(pid()) :: :ok
  def ignore_owner(pid) when is_pid(pid) do
    ignores =
      case :persistent_term.get(@ignore_key, nil) do
        %MapSet{} = set -> set
        _ -> MapSet.new()
      end

    :persistent_term.put(@ignore_key, MapSet.put(ignores, pid))
    :ok
  end

  @doc """
  Sets the process that receives injected `{:udp, socket, ip, port, data}` messages.

  Flushes any packets queued before an owner was set. Ignored owners (see
  `ignore_owner/1`) leave the previous owner unchanged.
  """
  @spec controlling_process(socket(), pid()) :: :ok
  def controlling_process(socket, pid) do
    term = :persistent_term.get({__MODULE__, socket})

    cond do
      ignored_owner?(pid) ->
        :ok

      term.owner == pid ->
        :ok

      true ->
        pending = term.pending
        demux = Map.get(term, :demux) || pid

        :persistent_term.put(
          {__MODULE__, socket},
          term
          |> Map.put(:owner, pid)
          |> Map.put(:demux, demux)
          |> Map.put(:pending, [])
        )

        pending
        |> Enum.reverse()
        |> Enum.each(fn {ip, port, data} ->
          _ = send(pid, {:udp, socket, ip, port, data})
        end)

        :ok
    end
  end

  defp ignored_owner?(pid) do
    case :persistent_term.get(@ignore_key, nil) do
      %MapSet{} = set -> MapSet.member?(set, pid)
      _ -> false
    end
  end

  @doc """
  Sends a DTLS datagram toward `ip`/`port`.

  When ICE-TCP or TURN relay send is armed, forwards via framed TCP or TURN
  instead of a direct UDP send.
  """
  @spec send(socket(), :inet.ip_address(), :inet.port_number(), iodata()) ::
          :ok | {:error, term()}
  def send(socket, ip, port, data) do
    data = IO.iodata_to_binary(data)
    remote = {ip, port}

    case :persistent_term.get({__MODULE__, socket}, nil) do
      %{tcp_sends: %{^remote => {tcp_sock, _}}} ->
        XGW.Stun.TCP.send(tcp_sock, data)

      %{relay_sends: %{^remote => {alloc, _peer, channel}}} when not is_nil(channel) ->
        frame = XGW.TURN.Client.encode_channel_data(channel, data)
        {tip, tport} = alloc.turn_server
        :gen_udp.send(socket, tip, tport, frame)

      %{relay_sends: %{^remote => {alloc, peer, _channel}}} ->
        indication = XGW.TURN.Client.send_indication(alloc, peer, data)
        {tip, tport} = alloc.turn_server
        :gen_udp.send(socket, tip, tport, indication)

      %{tcp_send: {tcp_sock, {pip, _pport}}} when pip == ip ->
        # ICE-TCP: DTLS records ride RFC 4571 frames on the nominated TCP socket.
        XGW.Stun.TCP.send(tcp_sock, data)

      %{relay_send: {alloc, _peer, channel}} when not is_nil(channel) ->
        frame = XGW.TURN.Client.encode_channel_data(channel, data)
        {tip, tport} = alloc.turn_server
        :gen_udp.send(socket, tip, tport, frame)

      %{relay_send: {alloc, peer, _channel}} ->
        indication = XGW.TURN.Client.send_indication(alloc, peer, data)
        {tip, tport} = alloc.turn_server
        :gen_udp.send(socket, tip, tport, indication)

      _ ->
        :gen_udp.send(socket, ip, port, data)
    end
  end

  @doc """
  Routes subsequent DTLS `send/4` datagrams as ICE-TCP framed payloads on `tcp_sock`.

  OTP cannot DTLS-upgrade a `gen_tcp` socket (`{:dtls_upgrade, :notsup}`); ICE-TCP
  therefore reuses the UDP DTLS stack and forwards records over the nominated TCP
  connection with RFC 4571 framing.
  """
  @spec set_tcp_send(socket(), port(), {:inet.ip_address(), :inet.port_number()}) :: :ok
  def set_tcp_send(socket, tcp_sock, peer) when is_port(tcp_sock) do
    term = :persistent_term.get({__MODULE__, socket})
    tcp_sends = Map.put(Map.get(term, :tcp_sends, %{}), peer, {tcp_sock, peer})

    :persistent_term.put(
      {__MODULE__, socket},
      term |> Map.put(:tcp_send, {tcp_sock, peer}) |> Map.put(:tcp_sends, tcp_sends)
    )

    :ok
  end

  @doc """
  Clears ICE-TCP send routing so `send/4` uses UDP (or TURN) again.

  With `peer`, clears only that remote on a shared Listener socket.
  """
  @spec clear_tcp_send(socket()) :: :ok
  @spec clear_tcp_send(socket(), {:inet.ip_address(), :inet.port_number()} | nil) :: :ok
  def clear_tcp_send(socket, peer \\ nil) do
    case :persistent_term.get({__MODULE__, socket}, nil) do
      %{} = term ->
        term =
          if is_nil(peer) do
            term |> Map.delete(:tcp_send) |> Map.delete(:tcp_sends)
          else
            tcp_sends = Map.delete(Map.get(term, :tcp_sends, %{}), peer)

            case Map.get(term, :tcp_send) do
              {_, ^peer} -> Map.delete(term, :tcp_send) |> Map.put(:tcp_sends, tcp_sends)
              _ -> Map.put(term, :tcp_sends, tcp_sends)
            end
          end

        :persistent_term.put({__MODULE__, socket}, term)
        :ok

      _ ->
        :ok
    end
  end

  @doc """
  Routes subsequent `send/4` datagrams through TURN toward `peer`.

  When `channel:` is set (0x4000..0x7FFF), uses ChannelData; otherwise Send Indication.
  Used after ICE nominates a relay local so DTLS appears to come from the relayed
  address (browser selected the relay path).
  """
  @spec set_relay_send(socket(), map(), {:inet.ip_address(), :inet.port_number()}, keyword()) ::
          :ok
  def set_relay_send(socket, allocation, peer, opts \\ []) when is_map(allocation) do
    channel = Keyword.get(opts, :channel)
    term = :persistent_term.get({__MODULE__, socket})
    entry = {allocation, peer, channel}
    relay_sends = Map.put(Map.get(term, :relay_sends, %{}), peer, entry)

    peer_by_owner =
      bind_peer_by_owner(Map.get(term, :peer_by_owner, %{}), Map.get(term, :inject_owners, %{}), peer, term)

    :persistent_term.put(
      {__MODULE__, socket},
      term
      |> Map.put(:relay_send, entry)
      |> Map.put(:relay_sends, relay_sends)
      |> Map.put(:peer_by_owner, peer_by_owner)
    )

    :ok
  end

  defp bind_peer_by_owner(peer_by_owner, inject_owners, remote, term) do
    case Map.get(inject_owners, remote) do
      pid when is_pid(pid) ->
        Map.put(peer_by_owner, pid, remote)

      _ ->
        case Map.get(term, :owner) do
          pid when is_pid(pid) -> Map.put(peer_by_owner, pid, remote)
          _ -> peer_by_owner
        end
    end
  end

  @doc """
  Clears TURN relay send routing.

  With `peer`, clears only that remote on a shared Listener socket.
  """
  @spec clear_relay_send(socket()) :: :ok
  @spec clear_relay_send(socket(), {:inet.ip_address(), :inet.port_number()} | nil) :: :ok
  def clear_relay_send(socket, peer \\ nil) do
    case :persistent_term.get({__MODULE__, socket}, nil) do
      %{} = term ->
        term =
          if is_nil(peer) do
            term
            |> Map.delete(:relay_send)
            |> Map.delete(:relay_sends)
            |> Map.delete(:peer_by_owner)
          else
            relay_sends = Map.delete(Map.get(term, :relay_sends, %{}), peer)

            peer_by_owner =
              term
              |> Map.get(:peer_by_owner, %{})
              |> Enum.reject(fn {_pid, r} -> r == peer end)
              |> Map.new()

            term =
              case Map.get(term, :relay_send) do
                {_, ^peer, _} -> Map.delete(term, :relay_send)
                _ -> term
              end

            term
            |> Map.put(:relay_sends, relay_sends)
            |> Map.put(:peer_by_owner, peer_by_owner)
          end

        :persistent_term.put({__MODULE__, socket}, term)
        :ok

      _ ->
        :ok
    end
  end

  @doc """
  Clears per-remote inject owner (multi-peer shared socket).
  """
  @spec clear_inject_owner(socket(), {:inet.ip_address(), :inet.port_number()}) :: :ok
  def clear_inject_owner(socket, remote) do
    case :persistent_term.get({__MODULE__, socket}, nil) do
      %{} = term ->
        owners = Map.delete(Map.get(term, :inject_owners, %{}), remote)

        peer_by_owner =
          term
          |> Map.get(:peer_by_owner, %{})
          |> Enum.reject(fn {_pid, r} -> r == remote end)
          |> Map.new()

        :persistent_term.put(
          {__MODULE__, socket},
          term
          |> Map.put(:inject_owners, owners)
          |> Map.put(:peer_by_owner, peer_by_owner)
        )

        :ok

      _ ->
        :ok
    end
  end

  @doc """
  Binds DTLS injects from `remote` to the current demux/owner (or `owner` if given).

  Used when a Peer arms DTLS for a selected ICE remote on a shared Listener socket.
  """
  @spec set_inject_owner(socket(), {:inet.ip_address(), :inet.port_number()}, pid() | nil) :: :ok
  def set_inject_owner(socket, remote, owner \\ nil) do
    case :persistent_term.get({__MODULE__, socket}, nil) do
      %{} = term ->
        owner = owner || Map.get(term, :owner)

        if is_pid(owner) do
          inject_owners = Map.put(Map.get(term, :inject_owners, %{}), remote, owner)

          peer_by_owner =
            cond do
              Map.has_key?(Map.get(term, :relay_sends, %{}), remote) ->
                Map.put(Map.get(term, :peer_by_owner, %{}), owner, remote)

              match?({_, ^remote, _}, Map.get(term, :relay_send)) ->
                Map.put(Map.get(term, :peer_by_owner, %{}), owner, remote)

              true ->
                Map.get(term, :peer_by_owner, %{})
            end

          :persistent_term.put(
            {__MODULE__, socket},
            term
            |> Map.put(:inject_owners, inject_owners)
            |> Map.put(:peer_by_owner, peer_by_owner)
          )
        end

        :ok

      _ ->
        :ok
    end
  end

  @doc """
  Restores the DTLS UDP owner to the packet demux (or clears it) and drops pending.

  Keeps `listener` / `relay_send` / `demux` entries. Used when restarting ICE/DTLS
  on a shared Listener so inbound injects still reach OTP's demux.
  """
  @spec reset_owner(socket()) :: :ok
  def reset_owner(socket) do
    case :persistent_term.get({__MODULE__, socket}, nil) do
      %{demux: demux} = term when is_pid(demux) ->
        :persistent_term.put(
          {__MODULE__, socket},
          term |> Map.put(:owner, demux) |> Map.put(:pending, [])
        )
        :ok

      %{} = term ->
        :persistent_term.put(
          {__MODULE__, socket},
          term |> Map.put(:owner, nil) |> Map.put(:pending, [])
        )
        :ok

      _ ->
        :ok
    end
  end

  @doc """
  No-op close for `:ssl` transport callbacks (Listener owns the UDP socket).
  """
  @spec close(socket()) :: :ok
  def close(_socket), do: :ok

  @doc """
  Applies inet options, ignoring `:active` / `:deliver` (Listener owns recv mode).
  """
  @spec setopts(socket(), keyword()) :: :ok | {:error, term()}
  def setopts(socket, opts) do
    opts = Enum.reject(opts, fn {k, _} -> k in [:active, :deliver] end)
    if opts == [], do: :ok, else: :inet.setopts(socket, opts)
  end

  @doc """
  Returns inet options for the underlying UDP socket.
  """
  @spec getopts(socket(), [atom()]) :: {:ok, keyword()} | {:error, term()}
  def getopts(socket, opts), do: :inet.getopts(socket, opts)

  @doc """
  Peer address for `:ssl` callbacks.

  When TURN relay send is armed, returns the remote ICE peer for this
  association (or the singleton); otherwise a placeholder (host DTLS over
  shared UDP is connectionless from OTP's view).
  """
  @spec peername(socket()) :: {:ok, {:inet.ip_address(), :inet.port_number()}}
  def peername(socket) do
    case :persistent_term.get({__MODULE__, socket}, nil) do
      %{peer_by_owner: owners, relay_sends: sends} = term ->
        case Map.get(owners, self()) do
          peer when is_map_key(sends, peer) ->
            {:ok, peer}

          _ ->
            case term do
              %{relay_send: {_alloc, peer, _channel}} when is_tuple(peer) ->
                {:ok, peer}

              _ ->
                {:ok, {{127, 0, 0, 1}, 0}}
            end
        end

      %{relay_send: {_alloc, peer, _channel}} when is_tuple(peer) ->
        {:ok, peer}

      _ ->
        {:ok, {{127, 0, 0, 1}, 0}}
    end
  end

  @doc """
  Local sockname via the owning Listener GenServer.
  """
  @spec sockname(socket()) :: {:ok, {:inet.ip_address(), :inet.port_number()}} | {:error, term()}
  def sockname(socket) do
    %{listener: listener} = :persistent_term.get({__MODULE__, socket})
    GenServer.call(listener, :sockname)
  end

  @doc """
  Local UDP port from `sockname/1`.
  """
  @spec port(socket()) :: :inet.port_number()
  def port(socket) do
    {:ok, {_ip, port}} = sockname(socket)
    port
  end

  @doc """
  Delivers an inbound DTLS datagram to the current owner, or queues until one is set.
  """
  @spec inject(socket(), :inet.ip_address(), :inet.port_number(), binary()) :: :ok
  def inject(socket, ip, port, data) do
    case :persistent_term.get({__MODULE__, socket}) do
      %{owner: pid} = term when is_pid(pid) ->
        owner = Map.get(Map.get(term, :inject_owners, %{}), {ip, port}, pid)

        if Process.alive?(owner) do
          _ = send(owner, {:udp, socket, ip, port, data})
          :ok
        else
          require Logger
          Logger.warning("xgw DTLS transport owner #{inspect(owner)} is dead; dropping inject")
          :ok
        end

      term ->
        pending = [{ip, port, data} | Map.get(term, :pending, [])]
        :persistent_term.put({__MODULE__, socket}, Map.put(term, :pending, pending))
        :ok
    end
  end
end
