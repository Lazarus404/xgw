defmodule XGW.Peer.Turn do
  @moduledoc """
  Peer-side TURN lifecycle: allocate, refresh, unwrap, and encode relay traffic.

  ## How this fits

  When local candidates include **relay** addresses, the Peer must keep TURN
  allocations alive, create permissions / channel bindings toward the selected
  remote, and wrap outbound UDP (including DTLS/SRTP) as Send Indication or
  ChannelData. Inbound TURN Data Indications are unwrapped before demux.

  Pure helpers and state transforms used by `XGW.Peer` (not a GenServer).

  ## RFCs

  * RFC 8656 -- TURN allocations, permissions, ChannelBind, Send Indication, ChannelData
  * RFC 8489 -- STUN encoding of TURN methods
  """

  require Logger

  alias XGW.{ICE, ICE.Full, ICE.Gather, Listener}
  alias XGW.DTLS.Transport
  alias XGW.Peer.SendHandle
  alias XGW.TURN.Client
  alias XMediaLib.{SDP.Candidate, Stun}

  @doc """
  Returns true when every relay local candidate has a covering TURN allocation.
  """
  @spec allocations_cover_relay_locals?(list(), list()) :: boolean()
  def allocations_cover_relay_locals?(allocs, locals) when is_list(allocs) and is_list(locals) do
    relay_locals = Enum.filter(locals, &(&1.type == "relay"))

    relay_locals != [] and
      Enum.all?(relay_locals, fn local ->
        Enum.any?(allocs, fn alloc ->
          {rip, rport} = alloc.relay
          local.ip == ICE.format_ip(rip) and local.port == rport
        end)
      end)
  end

  @doc """
  Returns true when peer state allocations cover current ICE relay locals.
  """
  @spec allocations_cover_relays?(map()) :: boolean()
  def allocations_cover_relays?(%{turn_allocations: allocs, ice: %{local_candidates: locals}}) do
    allocations_cover_relay_locals?(allocs, locals)
  end

  def allocations_cover_relays?(_), do: false

  @doc """
  Unwraps a TURN Data Indication to `{inner, peer_from}` or `:not_turn_data`.
  """
  @spec unwrap_data_indication(binary()) :: {:ok, binary(), {tuple(), integer()}} | :not_turn_data
  def unwrap_data_indication(data) when is_binary(data) do
    # DTLS/RTP must not hit Stun.decode (xmedialib can raise on non-STUN).
    case data do
      <<b, _::binary>> when b in 0..3 ->
        case safe_stun_decode(data) do
          {:ok, %Stun{class: :indication, method: :data, attrs: attrs}} ->
            with {ip, port} <- Map.get(attrs, :xor_peer_address),
                 inner when is_binary(inner) and inner != <<>> <- Map.get(attrs, :data) do
              {:ok, inner, {ip, port}}
            else
              _ -> :not_turn_data
            end

          _ ->
            :not_turn_data
        end

      _ ->
        :not_turn_data
    end
  end

  @doc """
  Encodes app data as Send Indication or ChannelData for the peer.
  """
  @spec encode_relay_app_data(map(), map(), term(), binary()) :: binary()
  def encode_relay_app_data(state, alloc, peer, data) do
    case Map.get(state.peer_channels, peer) do
      nil -> Client.send_indication(alloc, peer, data)
      channel -> Client.encode_channel_data(channel, data)
    end
  end

  @doc """
  Allocation used for outbound relay send, or nil when host path should win.
  """
  @spec relay_send_allocation(map()) :: map() | nil
  def relay_send_allocation(%{turn_allocations: []}), do: nil

  def relay_send_allocation(%{listener: listener, turn_allocations: [alloc | _]} = state)
      when is_pid(listener) do
    cond do
      Listener.relay_only?(listener) ->
        alloc

      match?(%{ice: %{nominated_pair: %{local: %{type: "relay"}}}}, state) ->
        alloc

      true ->
        nil
    end
  end

  def relay_send_allocation(_), do: nil

  @doc """
  Deletes allocations when they do not cover answer relay locals.
  """
  @spec maybe_delete_allocations(map(), map()) :: map()
  def maybe_delete_allocations(state, config) do
    if allocations_cover_relay_locals?(state.turn_allocations, config.local_candidates) do
      state
    else
      delete_allocations(state)
    end
  end

  @doc """
  Synchronous relay gather for prefetch.
  """
  @spec gather_relay(map()) :: list()
  def gather_relay(%{listener: listener}) when is_pid(listener) do
    sockname = Listener.sockname(listener)
    gather_opts = Listener.gather_opts(listener)
    timeout = Listener.gather_timeout_ms(listener)
    turn_credentials = Listener.turn_credentials(listener)

    send_recv = fn wire, {ip, port} ->
      Listener.turn_request(listener, ip, port, timeout, wire)
    end

    Gather.gather_relay(
      sockname,
      Keyword.merge(gather_opts,
        turn_servers: Listener.turn_servers(listener),
        turn_credentials: turn_credentials,
        query_timeout_ms: timeout,
        send_recv: send_recv
      )
    )
  end

  @doc """
  Merges gather_relay results into ICE/allocations and notifies the handler.

  Schedules TURN refresh; caller schedules connectivity-check ticks.
  """
  @spec apply_relay_results(map(), list()) :: map()
  def apply_relay_results(state, relay_results) do
    mid = hd(state.config.bundle_mids)

    state =
      Enum.reduce(relay_results, state, fn %{candidate: cand, allocation: allocation}, st ->
        had? =
          MapSet.member?(
            MapSet.new(st.ice.local_candidates, &candidate_key/1),
            candidate_key(cand)
          )

        {:ok, ice} = Full.add_local_candidate(st.ice, cand)
        config = %{st.config | local_candidates: ice.local_candidates}

        unless had? do
          send(
            st.handler,
            {:xgw, :local_candidate, self(), %{candidate: ICE.candidate_line(cand), mid: mid}}
          )
        end

        %{
          st
          | ice: ice,
            config: config,
            turn_allocations: st.turn_allocations ++ [allocation]
        }
      end)

    relay_cands = Enum.map(relay_results, & &1.candidate)
    ice = Full.extend_locals(state.ice, relay_cands)
    schedule_refresh_tick(%{state | ice: ice})
  end

  @doc """
  Best-effort TURN Refresh for each live allocation.
  """
  @spec refresh_allocations(map()) :: map()
  def refresh_allocations(%{listener: nil} = state), do: state
  def refresh_allocations(%{turn_allocations: []} = state), do: state

  def refresh_allocations(%{listener: listener, turn_allocations: allocations} = state) do
    timeout = Listener.gather_timeout_ms(listener)

    send_recv = fn wire, {ip, port} ->
      Listener.turn_request(listener, ip, port, timeout, wire)
    end

    refreshed =
      Enum.map(allocations, fn allocation ->
        lifetime = max(60, div(allocation.lifetime_s * 4, 5))

        case Client.refresh(send_recv, allocation, lifetime) do
          {:ok, alloc} -> alloc
          _ -> allocation
        end
      end)

    %{state | turn_allocations: refreshed}
  end

  @doc """
  Arms `:turn_refresh_tick` from the first allocation lifetime.
  """
  @spec schedule_refresh_tick(map()) :: map()
  def schedule_refresh_tick(%{turn_allocations: []} = state), do: state

  def schedule_refresh_tick(%{turn_allocations: [alloc | _]} = state) do
    ms = max(1_000, div(alloc.lifetime_s * 4, 5) * 1_000)
    ref = Process.send_after(self(), :turn_refresh_tick, ms)
    %{state | turn_refresh_timer: ref}
  end

  @doc """
  Cancels the TURN refresh timer when present.
  """
  @spec cancel_refresh_timer(map()) :: map()
  def cancel_refresh_timer(%{turn_refresh_timer: ref} = state) when is_reference(ref) do
    _ = Process.cancel_timer(ref)
    %{state | turn_refresh_timer: nil}
  end

  def cancel_refresh_timer(state), do: state

  @doc """
  After nomination on a relay pair, create permission + ChannelBind.
  """
  @spec maybe_create_permission(map(), map()) :: map()
  def maybe_create_permission(%{turn_allocations: []} = state, _ice), do: state

  def maybe_create_permission(%{listener: listener} = state, ice) do
    with %{nominated_pair: %{local: %{type: "relay"} = local, remote: remote}} <- ice,
         alloc when not is_nil(alloc) <- find_allocation(state, local),
         peer = ICE.endpoint(remote),
         true <- is_pid(listener) do
      bind_channel(state, alloc, peer)
    else
      _ -> state
    end
  end

  def maybe_create_permission(state, _ice), do: state

  @doc """
  Looks up a TURN allocation by relay local candidate.
  """
  @spec find_allocation(map(), map()) :: map() | nil
  def find_allocation(%{turn_allocations: allocations}, %{ip: ip, port: port}) do
    Enum.find(allocations, fn alloc ->
      {rip, rport} = alloc.relay
      ICE.format_ip(rip) == ip and rport == port
    end)
  end

  def find_allocation(_, _), do: nil

  @doc """
  Deletes all TURN allocations and clears channel maps.
  """
  @spec delete_allocations(map()) :: map()
  def delete_allocations(%{listener: nil} = state), do: clear_channels(state)
  def delete_allocations(%{turn_allocations: []} = state), do: clear_channels(state)

  def delete_allocations(%{listener: listener, turn_allocations: allocations} = state) do
    timeout = Listener.gather_timeout_ms(listener)

    send_recv = fn wire, {ip, port} ->
      Listener.turn_request(listener, ip, port, timeout, wire)
    end

    for allocation <- allocations, do: Client.delete(send_recv, allocation)

    clear_channels(%{state | turn_allocations: []})
  end

  @doc """
  Resets channel number maps.
  """
  @spec clear_channels(map()) :: map()
  def clear_channels(state) do
    %{state | turn_channels: %{}, peer_channels: %{}, next_turn_channel: 0x4000}
  end

  defp bind_channel(%{listener: listener} = state, alloc, peer) when is_pid(listener) do
    send_recv = fn wire, {tip, tport} ->
      Listener.turn_request(listener, tip, tport, Listener.gather_timeout_ms(listener), wire)
    end

    case Client.create_permission(send_recv, alloc, peer) do
      :ok ->
        :ok

      {:error, reason} ->
        Logger.warning("xgw createperm failed peer=#{inspect(peer)} reason=#{inspect(reason)}")
    end

    {channel, next} =
      case Map.get(state.peer_channels, peer) do
        nil ->
          case Listener.allocate_turn_channel(listener, self()) do
            {:ok, ch} -> {ch, ch + 1}
            _ -> {state.next_turn_channel, state.next_turn_channel + 1}
          end

        existing ->
          {existing, state.next_turn_channel}
      end

    case Client.channel_bind(send_recv, alloc, peer, channel) do
      :ok ->
        _ = Listener.bind_turn_channel(listener, self(), channel)

        state = %{
          state
          | turn_channels: Map.put(state.turn_channels, channel, peer),
            peer_channels: Map.put(state.peer_channels, peer, channel),
            next_turn_channel: next
        }

        refresh_outbound_after_channel(state, alloc, peer, channel)

      {:error, reason} ->
        Logger.warning(
          "xgw channelbind failed peer=#{inspect(peer)} channel=#{channel} reason=#{inspect(reason)}"
        )

        state
    end
  end

  defp bind_channel(state, _alloc, _peer), do: state

  # When ChannelBind completes after media is up, refresh ETS send path (indication -> channel)
  # and re-arm DTLS relay framing with the new channel number.
  defp refresh_outbound_after_channel(%{phase: :media, listener: listener} = state, alloc, peer, channel)
       when is_pid(listener) do
    udp = Listener.udp_sock(listener)
    _ = Transport.set_relay_send(udp, alloc, peer, channel: channel)
    _ = SendHandle.publish_peer_state(self(), state)
    state
  end

  defp refresh_outbound_after_channel(state, _alloc, _peer, _channel), do: state

  defp candidate_key(%Candidate{foundation: f, component_id: c, ip: ip, port: port}) do
    {f, c, ip, port}
  end

  defp safe_stun_decode(data) do
    Stun.decode(data)
  rescue
    _ -> :error
  catch
    _, _ -> :error
  end
end
