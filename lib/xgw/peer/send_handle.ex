defmodule XGW.Peer.SendHandle do
  @moduledoc """
  Hot-path outbound RTP without GenServer hops on Peer or Listener.

  ## Why a send handle exists

  After DTLS, every media packet must be **SRTP-encrypted** and written to UDP
  (or TURN-wrapped). Calling into the Peer GenServer for each packet adds
  latency and mailbox pressure. Instead, Peer publishes encrypt state into an
  ETS table; forwarders call `send_rtp/3` with a handle from
  `XGW.Peer.outbound_handle/1`.

  ICE-TCP has no hot handle (`{:error, :use_genserver}`); fall back to
  `XGW.Peer.send_rtp_async/3`.

  Benches/tests may call `publish_passthrough/2` (RTP) or
  `publish_dc_passthrough/2` (datachannel) to register a synchronous MFA sink
  so Forwarder takes the SendHandle success path without a Peer GenServer hop.

  Datachannel production egress uses the per-Peer `XGW.Peer.Datachannel` process
  (`Peer.send_datachannel_async/4` casts there when published). A full SCTP-in-ETS
  hot path is not shipped (`ssl_sock` ownership).

  ponytail: v1 assumes one packet writer per Peer outbound (forwarder). ROC
  write-back uses generation-matched `select_replace` so Peer republish cannot
  be clobbered. Multi-writer CAS across forwarders is the upgrade path.

  ## RFCs

  * RFC 3711 -- SRTP encrypt on the outbound hot path
  * RFC 8656 -- TURN ChannelData / Send Indication when the path is relay
  """

  alias XGW.SRTPSession
  alias XGW.TURN.Client
  alias XMediaLib.Rtp

  @table :xgw_peer_send

  @typedoc """
  Opaque handle used by `send_rtp/3`.

  ## Fields

  * `:peer` - Peer GenServer pid whose ETS row backs this handle
  * `:generation` - publish generation; stale handles fail closed after republish
  """
  @type t :: %__MODULE__{
          peer: pid(),
          generation: pos_integer()
        }

  @doc """
  Hot-path send handle.

  ## Fields

  * `:peer` - Peer GenServer pid whose ETS row backs this handle
  * `:generation` - publish generation; stale handles fail closed after republish
  """
  defstruct peer: nil, generation: nil

  @doc """
  Creates the ETS table (idempotent). Called from `XGW.Application`.
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

      _tid ->
        :ok
    end
  end

  @doc """
  Looks up a published handle for `peer`.

  Returns `{:error, :not_ready}` when missing, or `{:error, :use_genserver}` for
  ICE-TCP / GenServer-only rows.
  """
  @spec fetch(pid()) :: {:ok, t()} | {:error, :not_ready | :use_genserver}
  def fetch(peer) when is_pid(peer) do
    ensure_table!()

    case :ets.lookup(@table, peer) do
      [{^peer, :gen_server_only}] ->
        {:error, :use_genserver}

      [{^peer, generation, :passthrough, _mfa}] when is_integer(generation) ->
        {:ok, %__MODULE__{peer: peer, generation: generation}}

      [{^peer, generation, :dc_passthrough, _mfa}] when is_integer(generation) ->
        {:ok, %__MODULE__{peer: peer, generation: generation}}

      [{^peer, generation, :trunk_passthrough, _rtp, _dc}] when is_integer(generation) ->
        {:ok, %__MODULE__{peer: peer, generation: generation}}

      [{^peer, generation, _udp, _path, _srtp}] when is_integer(generation) ->
        {:ok, %__MODULE__{peer: peer, generation: generation}}

      [] ->
        {:error, :not_ready}
    end
  end

  @doc """
  Publishes RTP and datachannel passthrough MFAs in one ETS row so Forwarder
  can use both hot paths for the same peer pid (trunk pipe).
  """
  @spec publish_trunk_passthrough(pid(), {module(), atom(), pid()}, {module(), atom(), pid()}) ::
          :ok
  def publish_trunk_passthrough(peer, rtp_mfa, dc_mfa)
      when is_pid(peer) and is_tuple(rtp_mfa) and is_tuple(dc_mfa) do
    ensure_table!()
    generation = next_generation(peer)
    true = :ets.insert(@table, {peer, generation, :trunk_passthrough, rtp_mfa, dc_mfa})
    :ok
  end

  @doc """
  Publishes a plaintext passthrough sink for benches/tests (no SRTP/UDP).

  Forwarder prefers `send_rtp/3` when a handle exists. The MFA is invoked
  synchronously as `apply(mod, fun, [sink, ssrc, rtp])` so latency probes can
  record without a Peer GenServer hop. Used by latency benches and FakePeer tests.
  """
  @spec publish_passthrough(pid(), {module(), atom(), pid()}) :: :ok
  def publish_passthrough(peer, {mod, fun, sink} = mfa)
      when is_pid(peer) and is_atom(mod) and is_atom(fun) and is_pid(sink) do
    ensure_table!()
    generation = next_generation(peer)
    true = :ets.insert(@table, {peer, generation, :passthrough, mfa})
    :ok
  end

  @doc """
  Publishes a plaintext datachannel passthrough sink for benches/tests.

  Distinct from RTP `publish_passthrough/2` so MFA arity does not clash
  (`apply(mod, fun, [sink, channel_ref, data, type])` where `type` is
  `:string` | `:binary`).
  """
  @spec publish_dc_passthrough(pid(), {module(), atom(), term()}) :: :ok
  def publish_dc_passthrough(peer, {mod, fun, _sink} = mfa)
      when is_pid(peer) and is_atom(mod) and is_atom(fun) do
    ensure_table!()
    generation = next_generation(peer)
    true = :ets.insert(@table, {peer, generation, :dc_passthrough, mfa})
    :ok
  end

  @doc """
  Removes any ETS row for `peer`.
  """
  @spec invalidate(pid()) :: :ok
  def invalidate(peer) when is_pid(peer) do
    ensure_table!()
    true = :ets.delete(@table, peer)
    :ok
  end

  @doc """
  Hot-path datachannel send when a `:dc_passthrough` row is published.

  `type` is `:string` (PPI 51) or `:binary` (PPI 53); passed to the MFA as the
  fourth argument so benches can observe PPI. Production Peer fallback uses the
  same type via `XGW.Peer.send_datachannel_async/4`.

  Returns `{:error, :not_ready}` when missing, `{:error, :stale}` on generation
  mismatch, or `{:error, :use_genserver}` for GenServer-only / RTP rows (caller
  should fall back to `XGW.Peer.send_datachannel_async/4`).
  """
  @spec send_datachannel(t() | pid(), reference(), binary(), :string | :binary) ::
          :ok | {:error, term()}
  def send_datachannel(handle_or_peer, channel_ref, data, type \\ :string)

  def send_datachannel(%__MODULE__{peer: peer, generation: generation}, channel_ref, data, type)
      when is_reference(channel_ref) and is_binary(data) and type in [:string, :binary] do
    do_send_datachannel(peer, generation, channel_ref, data, type)
  end

  def send_datachannel(peer, channel_ref, data, type)
      when is_pid(peer) and is_reference(channel_ref) and is_binary(data) and
             type in [:string, :binary] do
    ensure_table!()

    case :ets.lookup(@table, peer) do
      [{^peer, generation, :dc_passthrough, _}] when is_integer(generation) ->
        do_send_datachannel(peer, generation, channel_ref, data, type)

      [{^peer, generation, :trunk_passthrough, _rtp, _dc}] when is_integer(generation) ->
        do_send_datachannel(peer, generation, channel_ref, data, type)

      [{^peer, :gen_server_only}] ->
        {:error, :use_genserver}

      [{^peer, _gen, :passthrough, _}] ->
        {:error, :use_genserver}

      [{^peer, _gen, _udp, _path, _srtp}] ->
        {:error, :use_genserver}

      [] ->
        {:error, :not_ready}
    end
  end

  defp do_send_datachannel(peer, generation, channel_ref, data, type) do
    ensure_table!()

    case :ets.lookup(@table, peer) do
      [{^peer, ^generation, :dc_passthrough, {mod, fun, sink}}] ->
        apply(mod, fun, [sink, channel_ref, data, type])

      [{^peer, ^generation, :trunk_passthrough, _rtp, {mod, fun, sink}}] ->
        apply(mod, fun, [sink, channel_ref, data, type])

      [{^peer, _other_gen, :dc_passthrough, _}] ->
        {:error, :stale}

      [{^peer, _other_gen, :trunk_passthrough, _, _}] ->
        {:error, :stale}

      [{^peer, :gen_server_only}] ->
        {:error, :use_genserver}

      [] ->
        {:error, :not_ready}

      _ ->
        {:error, :use_genserver}
    end
  end

  @doc """
  Publishes or refreshes the hot-path row from Peer GenServer state.

  Preserves existing ETS encrypt contexts across path republish. TCP selected
  transport stores a GenServer-only marker (no UDP hot path).
  """
  @spec publish_peer_state(pid(), map()) :: :ok
  def publish_peer_state(peer, state) when is_pid(peer) and is_map(state) do
    ensure_table!()

    cond do
      state[:phase] != :media or is_nil(state[:srtp]) or is_nil(state[:selected]) ->
        invalidate(peer)

      state[:selected_transport] == :tcp ->
        true = :ets.insert(@table, {peer, :gen_server_only})
        :ok

      not is_pid(state[:listener]) ->
        invalidate(peer)

      true ->
        udp = XGW.Listener.udp_sock(state.listener)
        path = build_path(state)
        srtp = outbound_srtp(peer, state.srtp)
        generation = next_generation(peer)
        true = :ets.insert(@table, {peer, generation, udp, path, srtp})
        :ok
    end
  end

  @doc """
  Encrypts and sends one RTP packet on the hot path.

  On success: no Peer or Listener GenServer involvement.
  """
  @spec send_rtp(t() | pid(), non_neg_integer(), binary() | Rtp.t()) :: :ok | {:error, term()}
  def send_rtp(%__MODULE__{peer: peer, generation: generation}, ssrc, packet) do
    do_send_rtp(peer, generation, ssrc, packet)
  end

  def send_rtp(peer, ssrc, packet) when is_pid(peer) do
    case fetch(peer) do
      {:ok, handle} -> send_rtp(handle, ssrc, packet)
      {:error, _} = err -> err
    end
  end

  defp do_send_rtp(peer, generation, ssrc, packet) do
    ensure_table!()

    case :ets.lookup(@table, peer) do
      [{^peer, :gen_server_only}] ->
        {:error, :use_genserver}

      [{^peer, ^generation, :passthrough, {mod, fun, sink}}] ->
        with {:ok, rtp} <- normalize_rtp(packet, ssrc) do
          apply(mod, fun, [sink, ssrc, rtp])
        end

      [{^peer, ^generation, :trunk_passthrough, {mod, fun, sink}, _dc}] ->
        with {:ok, rtp} <- normalize_rtp(packet, ssrc) do
          apply(mod, fun, [sink, ssrc, rtp])
        end

      [{^peer, ^generation, udp, path, srtp}] ->
        with {:ok, rtp} <- normalize_rtp(packet, ssrc),
             {:ok, wire, srtp2} <- SRTPSession.encrypt(srtp, :rtp, rtp),
             1 <- replace_srtp(peer, generation, udp, path, srtp2),
             :ok <- wire_send(udp, path, wire) do
          :ok
        else
          0 ->
            {:error, :stale}

          {:error, %SRTPSession{}} ->
            {:error, :encrypt_failed}

          {:error, reason} ->
            {:error, reason}

          _ ->
            {:error, :invalid_packet}
        end

      [{^peer, _other_gen, :passthrough, _}] ->
        {:error, :stale}

      [{^peer, _other_gen, :trunk_passthrough, _, _}] ->
        {:error, :stale}

      [{^peer, _other_gen, _, _, _}] ->
        {:error, :stale}

      [] ->
        {:error, :not_ready}
    end
  end

  defp replace_srtp(peer, generation, _udp, _path, srtp) do
    # Match peer+generation only; keep live udp/path from the row so a concurrent
    # path republish with the same generation cannot be clobbered by a stale path.
    # New generation (Peer republish) yields 0 replacements.
    :ets.select_replace(@table, [
      {
        {peer, generation, :"$1", :"$2", :"$3"},
        [],
        [{{peer, generation, :"$1", :"$2", {:const, srtp}}}]
      }
    ])
  end

  defp wire_send(udp, {:host, {ip, port}}, wire) do
    :gen_udp.send(udp, ip, port, wire)
  end

  defp wire_send(udp, {:turn_channel, {tip, tport}, channel}, wire) do
    frame = Client.encode_channel_data(channel, wire)
    :gen_udp.send(udp, tip, tport, frame)
  end

  defp wire_send(udp, {:turn_ind, {tip, tport}, alloc, peer}, wire) do
    frame = Client.send_indication(alloc, peer, wire)
    :gen_udp.send(udp, tip, tport, frame)
  end

  defp wire_send(_udp, _path, _wire), do: {:error, :no_selected_pair}

  defp build_path(state) do
    peer = state.selected

    case XGW.Peer.Turn.relay_send_allocation(state) do
      nil ->
        {:host, peer}

      alloc ->
        turn_server = alloc.turn_server

        case Map.get(state.peer_channels || %{}, peer) do
          nil ->
            {:turn_ind, turn_server, alloc, peer}

          channel ->
            {:turn_channel, turn_server, channel}
        end
    end
  end

  defp outbound_srtp(peer, %SRTPSession{} = srtp) do
    case :ets.lookup(@table, peer) do
      [{^peer, _gen, _udp, _path, %SRTPSession{} = existing}] ->
        # Keep ROC/encrypt contexts across path republish; refresh keys if rotated.
        %{
          existing
          | server_key: srtp.server_key,
            server_salt: srtp.server_salt,
            client_key: nil,
            client_salt: nil,
            decrypt_contexts: %{}
        }

      _ ->
        SRTPSession.outbound(srtp)
    end
  end

  defp next_generation(peer) do
    case :ets.lookup(@table, peer) do
      [{^peer, gen, :passthrough, _}] when is_integer(gen) -> gen + 1
      [{^peer, gen, :dc_passthrough, _}] when is_integer(gen) -> gen + 1
      [{^peer, gen, :trunk_passthrough, _, _}] when is_integer(gen) -> gen + 1
      [{^peer, gen, _, _, _}] when is_integer(gen) -> gen + 1
      _ -> 1
    end
  end

  defp normalize_rtp(%Rtp{} = rtp, ssrc), do: {:ok, %{rtp | ssrc: ssrc}}

  defp normalize_rtp(packet, ssrc) when is_binary(packet) do
    case Rtp.decode(packet) do
      {:ok, rtp} -> {:ok, %{rtp | ssrc: ssrc}}
      error -> error
    end
  end

  defp normalize_rtp(_, _), do: {:error, :invalid_packet}
end
