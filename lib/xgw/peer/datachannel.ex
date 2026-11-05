defmodule XGW.Peer.Datachannel do
  @moduledoc """
  Per-Peer process that owns SCTP and DTLS application-data for data channels.

  ## What problem this solves

  Production datachannel egress used to run on the `XGW.Peer` GenServer mailbox
  together with ICE, RTP, and consent. Under fanout load, synchronous
  `SctpAssociation.send/4` plus `:ssl.send/2` queued behind (and blocked) those
  duties, so wire latency climbed into seconds. This process isolates SCTP and
  DTLS app-data: Forwarder casts land here, and Peer stays responsive for media.

  Casts are drained in batches (default up to 32) so multiple user messages can
  share one flush of transmit events under load. Handler callbacks still use the
  Peer pid as `peer_ref` so Session and Forwarder identity is unchanged.

  A full SCTP-in-ETS SendHandle hot path is not shipped (`ssl_sock` ownership).

  ## RFCs

  * RFC 8261 -- SCTP over DTLS
  * RFC 8831 -- WebRTC data channels
  * RFC 8841 -- SDP negotiation of SCTP
  """

  use GenServer

  require Logger

  alias XGW.Peer.Sctp
  alias XSockets.Sctp.Association, as: SctpAssociation

  @table :xgw_peer_datachannel
  @default_batch_max 32

  @typedoc "Opaque options for `start_link/1`."
  @type start_opt ::
          {:peer, pid()}
          | {:handler, pid()}
          | {:ssl_sock, term()}
          | {:role, :active | :passive}
          | {:assoc, SctpAssociation.t()}
          | {:send_dtls, (map(), binary() -> :ok | {:error, term()})}
          | {:batch_max, pos_integer()}
          | {:sctp_ports, map()}

  @doc """
  Creates the ETS peer->Datachannel map (idempotent). Called from `XGW.Application`.
  """
  @spec ensure_table!() :: :ok
  def ensure_table! do
    case :ets.whereis(@table) do
      :undefined ->
        _ =
          :ets.new(@table, [
            :named_table,
            :public,
            :set,
            read_concurrency: true,
            write_concurrency: true
          ])

        :ok

      _ ->
        :ok
    end
  end

  @doc """
  Looks up the Datachannel pid published for `peer`, if any.
  """
  @spec lookup(pid()) :: {:ok, pid()} | :error
  def lookup(peer) when is_pid(peer) do
    ensure_table!()

    case :ets.lookup(@table, peer) do
      [{^peer, dc}] when is_pid(dc) -> {:ok, dc}
      _ -> :error
    end
  end

  @doc """
  Starts a Datachannel process for `peer`.

  When `ssl_sock` is present, takes over `:ssl.controlling_process/2` so DTLS
  app-data messages arrive here. Optional `:assoc` injects an existing
  association (tests). Optional `:send_dtls` replaces `:ssl.send/2` (tests).
  """
  @spec start_link([start_opt()]) :: GenServer.on_start()
  def start_link(opts) when is_list(opts) do
    _ = Keyword.fetch!(opts, :peer)
    _ = Keyword.fetch!(opts, :handler)
    GenServer.start_link(__MODULE__, opts)
  end

  @doc """
  Queues a user message on this Datachannel process (cast; batched drain).
  """
  @spec send_datachannel_async(pid(), reference(), binary(), :string | :binary) :: :ok
  def send_datachannel_async(dc, channel_ref, data, type \\ :string)
      when is_pid(dc) and is_reference(channel_ref) and is_binary(data) and
             type in [:string, :binary] do
    GenServer.cast(dc, {:send_datachannel, channel_ref, data, type})
  end

  @doc """
  Sends a user message and waits for SCTP/DTLS flush on this process.
  """
  @spec send_datachannel(pid(), reference(), binary(), :string | :binary) ::
          :ok | {:error, term()}
  def send_datachannel(dc, channel_ref, data, type \\ :string)
      when is_pid(dc) and is_reference(channel_ref) and is_binary(data) and
             type in [:string, :binary] do
    GenServer.call(dc, {:send_datachannel, channel_ref, data, type})
  end

  @doc """
  Opens a local data channel after the association is connected.
  """
  @spec open_datachannel(pid(), binary(), keyword()) :: {:ok, map()} | {:error, term()}
  def open_datachannel(dc, label, opts \\ [])
      when is_pid(dc) and is_binary(label) and label != "" and is_list(opts) do
    GenServer.call(dc, {:open_datachannel, label, opts})
  end

  @impl true
  def init(opts) do
    peer = Keyword.fetch!(opts, :peer)
    handler = Keyword.fetch!(opts, :handler)
    ssl_sock = Keyword.get(opts, :ssl_sock)
    role = Keyword.get(opts, :role, :passive)
    batch_max = Keyword.get(opts, :batch_max, @default_batch_max)
    send_dtls = Keyword.get(opts, :send_dtls) || (&default_send_dtls/2)
    sctp_ports = Keyword.get(opts, :sctp_ports)
    Process.flag(:trap_exit, true)
    _peer_mon = Process.monitor(peer)

    assoc =
      case Keyword.get(opts, :assoc) do
        %{} = existing ->
          existing

        _ ->
          if sctp_available?() do
            SctpAssociation.new(role: role)
          else
            nil
          end
      end

    _ = take_over_ssl(ssl_sock)

    ensure_table!()
    true = :ets.insert(@table, {peer, self()})

    if is_map(sctp_ports) do
      Logger.info(
        "xgw peer datachannel ready (role=#{role}, ports local=#{sctp_ports.local_port} remote=#{sctp_ports.remote_port})"
      )
    else
      Logger.debug("xgw peer datachannel ready (role=#{role})")
    end

    {:ok,
     %{
       peer: peer,
       handler: handler,
       ssl_sock: ssl_sock,
       sctp: assoc,
       send_dtls: send_dtls,
       batch_max: max(1, batch_max)
     }}
  end

  @impl true
  def handle_call({:send_datachannel, channel_ref, data, type}, _from, state) do
    {reply, state} = do_send_one(state, channel_ref, data, type)
    {:reply, reply, state}
  end

  def handle_call({:open_datachannel, label, opts}, _from, state) do
    {reply, state} = do_open(state, label, opts)
    {:reply, reply, state}
  end

  @impl true
  def handle_cast({:send_datachannel, channel_ref, data}, state) do
    handle_cast({:send_datachannel, channel_ref, data, :string}, state)
  end

  def handle_cast({:send_datachannel, channel_ref, data, type}, state)
      when type in [:string, :binary] do
    rest = drain_sends(state.batch_max - 1)
    batch = [{channel_ref, data, type} | rest]
    state = send_batch(state, batch)
    {:noreply, state}
  end

  @impl true
  def handle_info({:ssl, _ssl_sock, data}, %{ssl_sock: sock, sctp: assoc} = state)
      when not is_nil(sock) and not is_nil(assoc) do
    _ = maybe_setopts_once(sock)

    try do
      bin = IO.iodata_to_binary(data)
      Logger.debug("xgw datachannel DTLS app data #{byte_size(bin)} bytes")
      {events, assoc} = SctpAssociation.handle_packet(assoc, bin)
      {:noreply, flush(state, assoc, events)}
    rescue
      ArgumentError ->
        Logger.warning("xgw datachannel ignored non-iodata ssl payload: #{inspect(data)}")
        {:noreply, state}
    end
  end

  def handle_info({:ssl, _ssl_sock, _data}, %{ssl_sock: sock} = state) when not is_nil(sock) do
    _ = maybe_setopts_once(sock)
    {:noreply, state}
  end

  def handle_info({:ssl_closed, _ssl_sock}, state) do
    notify_peer_down(state, :ssl_closed)
    {:stop, :normal, clear_transport(state)}
  end

  def handle_info({:ssl_error, _ssl_sock, reason}, state) do
    Logger.warning("xgw datachannel ssl error: #{inspect(reason)}")
    {:noreply, state}
  end

  def handle_info(:sctp_timeout, %{sctp: assoc} = state) when not is_nil(assoc) do
    {events, assoc} = SctpAssociation.handle_timeout(assoc)
    {:noreply, flush(state, assoc, events)}
  end

  def handle_info(:sctp_timeout, state), do: {:noreply, state}

  def handle_info({:DOWN, _ref, :process, peer, _reason}, %{peer: peer} = state) do
    {:stop, :normal, clear_transport(state)}
  end

  def handle_info(_other, state), do: {:noreply, state}

  @impl true
  def terminate(_reason, state) do
    unpublish(state.peer)
    state
  end

  defp send_batch(%{sctp: nil} = state, batch) do
    :telemetry.execute(
      [:xgw, :peer, :dc_batch],
      %{size: length(batch)},
      %{peer: state.peer}
    )

    Enum.each(batch, fn {channel_ref, data, type} ->
      emit_dc_send_error(state, channel_ref, :no_sctp)

      Logger.warning(
        "xgw datachannel send fail=:no_sctp ref=#{inspect(channel_ref)} bytes=#{byte_size(data)} type=#{type}"
      )
    end)

    state
  end

  defp send_batch(state, batch) do
    :telemetry.execute(
      [:xgw, :peer, :dc_batch],
      %{size: length(batch)},
      %{peer: state.peer}
    )

    t0 = System.monotonic_time(:microsecond)

    {events, assoc} =
      Enum.reduce(batch, {[], state.sctp}, fn {channel_ref, data, type}, {evs, a} ->
        case SctpAssociation.send(a, channel_ref, data, type) do
          {more, a2} ->
            Logger.debug(
              "xgw datachannel send bytes=#{byte_size(data)} ref=#{inspect(channel_ref)} type=#{type} ok"
            )

            {evs ++ more, a2}

          {:error, reason, a2} ->
            level = if reason in [:unknown_channel, :not_open, :no_sctp], do: :debug, else: :warning

            Logger.log(
              level,
              "xgw datachannel send bytes=#{byte_size(data)} ref=#{inspect(channel_ref)} type=#{type} fail=#{inspect(reason)}"
            )

            emit_dc_send_error(state, channel_ref, reason)
            {evs, a2}
        end
      end)

    state = flush(state, assoc, events)
    maybe_profile(t0, events)
    state
  end

  defp do_send_one(%{sctp: assoc} = state, channel_ref, data, type)
       when not is_nil(assoc) and type in [:string, :binary] do
    t0 = System.monotonic_time(:microsecond)

    case SctpAssociation.send(assoc, channel_ref, data, type) do
      {events, assoc} ->
        Logger.debug(
          "xgw datachannel send bytes=#{byte_size(data)} ref=#{inspect(channel_ref)} type=#{type} ok"
        )

        state = flush(state, assoc, events)
        maybe_profile(t0, events)
        {:ok, state}

      {:error, reason, assoc} ->
        Logger.warning(
          "xgw datachannel send bytes=#{byte_size(data)} ref=#{inspect(channel_ref)} type=#{type} fail=#{inspect(reason)}"
        )

        emit_dc_send_error(state, channel_ref, reason)
        {{:error, reason}, %{state | sctp: assoc}}
    end
  end

  defp do_send_one(state, channel_ref, data, type) do
    Logger.warning(
      "xgw datachannel send fail=:no_sctp ref=#{inspect(channel_ref)} bytes=#{byte_size(data)} type=#{type}"
    )

    emit_dc_send_error(state, channel_ref, :no_sctp)
    {{:error, :no_sctp}, state}
  end

  defp do_open(%{sctp: assoc} = state, label, opts) when not is_nil(assoc) do
    case SctpAssociation.open_channel(assoc, label, opts) do
      {events, channel_ref, assoc} ->
        state = flush(state, assoc, events)
        info = channel_info(state.sctp, channel_ref, label)
        send(state.handler, {:xgw, :datachannel, state.peer, info})
        {{:ok, info}, state}

      {:error, reason, assoc} ->
        {{:error, reason}, %{state | sctp: assoc}}
    end
  end

  defp do_open(state, _label, _opts), do: {{:error, :not_connected}, state}

  defp flush(state, assoc, events) do
    st = %{state | sctp: assoc, peer: state.peer, handler: state.handler}
    Sctp.flush_events(st, events, state.send_dtls)
  end

  defp drain_sends(0), do: []

  defp drain_sends(n) when n > 0 do
    receive do
      {:"$gen_cast", {:send_datachannel, channel_ref, data, type}}
      when type in [:string, :binary] ->
        [{channel_ref, data, type} | drain_sends(n - 1)]

      {:"$gen_cast", {:send_datachannel, channel_ref, data}} ->
        [{channel_ref, data, :string} | drain_sends(n - 1)]
    after
      0 ->
        []
    end
  end

  defp default_send_dtls(%{ssl_sock: sock}, data)
       when not is_nil(sock) and is_binary(data) and sock != :fake_sock do
    :ssl.send(sock, data)
  end

  defp default_send_dtls(_, _), do: {:error, :no_ssl}

  defp take_over_ssl(sock) when sock in [nil, :fake_sock], do: :ok

  defp take_over_ssl(sock) do
    case :ssl.controlling_process(sock, self()) do
      :ok ->
        _ = :ssl.setopts(sock, mode: :binary, active: :once)
        :ok

      {:error, reason} ->
        Logger.warning("xgw datachannel controlling_process failed: #{inspect(reason)}")
        {:error, reason}
    end
  end

  defp maybe_setopts_once(sock) when sock in [nil, :fake_sock], do: :ok

  defp maybe_setopts_once(sock) do
    _ = :ssl.setopts(sock, mode: :binary, active: :once)
    :ok
  rescue
    _ -> :ok
  end

  defp clear_transport(state) do
    unpublish(state.peer)
    %{state | ssl_sock: nil, sctp: nil}
  end

  defp notify_peer_down(%{peer: peer}, reason) when is_pid(peer) do
    if Process.alive?(peer) do
      send(peer, {:xgw_internal, :datachannel_down, self(), reason})
    end

    :ok
  end

  defp unpublish(peer) when is_pid(peer) do
    ensure_table!()
    :ets.delete(@table, peer)
    :ok
  end

  defp emit_dc_send_error(state, channel_ref, reason) do
    :telemetry.execute(
      [:xgw, :peer, :dc_send_error],
      %{count: 1},
      %{reason: reason, channel_ref: channel_ref}
    )

    handler = Map.get(state, :handler)
    peer = Map.get(state, :peer) || self()

    if is_pid(handler) do
      send(handler, {:xgw, :datachannel_send_error, peer, channel_ref, reason})
    end

    :ok
  end

  defp channel_info(%{channels: channels}, channel_ref, label) when is_map(channels) do
    case Map.get(channels, channel_ref) do
      %{id: id} = ch when is_integer(id) ->
        %{
          ref: channel_ref,
          label: Map.get(ch, :label, label),
          id: id,
          reliability: Map.get(ch, :reliability),
          order: if(Map.get(ch, :ordered, true), do: :ordered, else: :unordered),
          param: Map.get(ch, :param)
        }

      _ ->
        %{ref: channel_ref, label: label, id: -1}
    end
  end

  defp channel_info(_, channel_ref, label), do: %{ref: channel_ref, label: label, id: -1}

  defp maybe_profile(t0, events) do
    if System.get_env("XYLON_DC_PROFILE") in ["1", "true", "yes"] and
         :erlang.phash2(t0, 200) == 0 do
      mb =
        case Process.info(self(), :message_queue_len) do
          {:message_queue_len, n} -> n
          _ -> -1
        end

      Logger.warning(
        "xgw dc profile send_us=#{System.monotonic_time(:microsecond) - t0} mb=#{mb} events=#{length(events)}"
      )
    end
  end

  defp sctp_available? do
    Code.ensure_loaded?(SctpAssociation) and SctpAssociation.available?()
  end
end
