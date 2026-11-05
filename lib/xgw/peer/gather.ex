defmodule XGW.Peer.Gather do
  @moduledoc """
  Post-SDP local candidate checks and background srflx/relay gather for a Peer.

  ## Why this sits beside `XGW.Peer`

  After `apply_descriptions/4`, a full-ICE Peer may still need server-reflexive
  or TURN relay candidates that were not ready when the answer was sent. This
  module (pure helpers + Task starters, not a GenServer) verifies that answer
  locals match Listener gather expectations and kicks off async gather that
  later emits `{:xgw, :local_candidate, ...}` / completion events via Peer.

  ## RFCs

  * RFC 8445 -- trickle / post-answer gather of srflx and relay locals
  * RFC 8489 -- STUN Binding for srflx
  * RFC 8656 -- TURN Allocate for relay
  """

  alias XGW.{ICE, ICE.Full, ICE.Gather, Listener}
  alias XGW.Peer.Turn
  alias XMediaLib.SDP.Candidate

  @doc """
  Returns host candidates that do not yet have an srflx with the same foundation.

  Used to decide whether post-apply STUN gather still has work to do.

  ## Examples

      iex> hosts = [%{type: "host", foundation: "1"}, %{type: "host", foundation: "2"}]
      iex> locals = hosts ++ [%{type: "srflx", foundation: "1"}]
      iex> XGW.Peer.Gather.hosts_missing_srflx(locals)
      [%{type: "host", foundation: "2"}]
  """
  @spec hosts_missing_srflx([Candidate.t() | map()]) :: [Candidate.t() | map()]
  def hosts_missing_srflx(locals) do
    hosts = Enum.filter(locals, &(&1.type == "host"))

    srflx_foundations =
      locals
      |> Enum.filter(&(&1.type == "srflx"))
      |> MapSet.new(& &1.foundation)

    Enum.reject(hosts, fn h -> MapSet.member?(srflx_foundations, h.foundation) end)
  end

  @doc """
  Dedup key for a local ICE candidate (`foundation`, component, ip, port).

  ## Examples

      iex> c = %XMediaLib.SDP.Candidate{
      ...>   foundation: "1", component_id: 1, ip: "192.0.2.1", port: 5000
      ...> }
      iex> XGW.Peer.Gather.candidate_key(c)
      {"1", 1, "192.0.2.1", 5000}
  """
  @spec candidate_key(Candidate.t()) :: {term(), term(), term(), term()}
  def candidate_key(%Candidate{foundation: f, component_id: c, ip: ip, port: port}) do
    {f, c, ip, port}
  end

  @doc """
  Ensures answer locals match Listener gather expectations (full ICE only).

  Returns `:ok` for ICE-lite or when no Listener is attached.
  """
  @spec verify_local_candidates(map(), map()) :: :ok | {:error, :local_candidate_mismatch}
  def verify_local_candidates(%{ice_lite: true}, _config), do: :ok
  def verify_local_candidates(%{listener: nil}, _config), do: :ok

  def verify_local_candidates(%{listener: listener}, config) do
    with :ok <- verify_host_locals(listener, config),
         :ok <- verify_srflx_locals(listener, config),
         :ok <- verify_relay_locals(listener, config) do
      :ok
    end
  end

  @doc """
  Starts async srflx gather when STUN servers and missing hosts exist.
  """
  @spec start_post_apply_srflx(map()) :: map()
  def start_post_apply_srflx(%{ice_lite: true} = state), do: state
  def start_post_apply_srflx(%{listener: nil} = state), do: state

  def start_post_apply_srflx(state) do
    listener = state.listener
    stun_servers = Listener.stun_servers(listener)

    if stun_servers == [] do
      state
    else
      hosts = hosts_missing_srflx(state.ice.local_candidates)

      if hosts == [] do
        state
      else
        task =
          Task.async(fn ->
            sockname = Listener.sockname(listener)
            gather_opts = Listener.gather_opts(listener)
            timeout = Listener.gather_timeout_ms(listener)

            send_recv = fn wire, {ip, port} ->
              Listener.turn_request(listener, ip, port, timeout, wire)
            end

            Gather.gather_srflx(
              sockname,
              hosts,
              Keyword.merge(gather_opts,
                stun_servers: stun_servers,
                query_timeout_ms: timeout,
                send_recv: send_recv
              )
            )
          end)

        %{state | srflx_task: task}
      end
    end
  end

  @doc """
  Starts async relay gather when TURN is configured and locals uncovered.
  """
  @spec start_post_apply_relay(map()) :: map()
  def start_post_apply_relay(%{ice_lite: true} = state), do: state
  def start_post_apply_relay(%{listener: nil} = state), do: state

  def start_post_apply_relay(state) do
    listener = state.listener

    cond do
      Listener.turn_servers(listener) == [] ->
        state

      Turn.allocations_cover_relays?(state) ->
        state

      true ->
        task =
          Task.async(fn ->
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
          end)

        %{state | relay_task: task}
    end
  end

  @doc """
  Merges gathered srflx into ICE and notifies the handler.

  Caller schedules connectivity-check ticks after this returns.
  """
  @spec apply_srflx_candidates(map(), [Candidate.t()]) :: map()
  def apply_srflx_candidates(state, srflx) do
    mid = hd(state.config.bundle_mids)

    Enum.reduce(srflx, state, fn cand, st ->
      {:ok, ice} = Full.add_local_candidate(st.ice, cand)

      send(
        st.handler,
        {:xgw, :local_candidate, self(), %{candidate: ICE.candidate_line(cand), mid: mid}}
      )

      config = %{st.config | local_candidates: ice.local_candidates}
      %{st | ice: ice, config: config}
    end)
    |> then(fn state ->
      ice = Full.extend_locals(state.ice, srflx)
      %{state | ice: ice}
    end)
  end

  @doc """
  Notifies handler when post-apply gather tasks have finished.
  """
  @spec maybe_emit_local_candidates_complete(map()) :: map()
  def maybe_emit_local_candidates_complete(%{closed?: true} = state), do: state
  def maybe_emit_local_candidates_complete(%{ice_lite: true} = state), do: state
  def maybe_emit_local_candidates_complete(%{local_gather_complete?: true} = state), do: state
  def maybe_emit_local_candidates_complete(%{srflx_task: %Task{}} = state), do: state
  def maybe_emit_local_candidates_complete(%{relay_task: %Task{}} = state), do: state

  def maybe_emit_local_candidates_complete(state) do
    send(state.handler, {:xgw, :local_candidates_complete, self()})
    %{state | local_gather_complete?: true}
  end

  defp verify_host_locals(listener, config) do
    sockname = Listener.sockname(listener)
    gather_opts = Listener.gather_opts(listener)
    expected_udp = Gather.host_candidates(sockname, gather_opts)
    expected_udp_keys = MapSet.new(expected_udp, &candidate_key/1)

    expected_tcp_keys =
      if Listener.ice_tcp_enabled?(listener) and Listener.tcp_port(listener) do
        {ip, _} = sockname

        Gather.tcp_passive_candidates({ip, Listener.tcp_port(listener)}, gather_opts)
        |> MapSet.new(&candidate_key/1)
      else
        MapSet.new()
      end

    host_locals = Enum.filter(config.local_candidates, &(&1.type == "host"))
    udp_hosts = Enum.filter(host_locals, &(String.downcase(&1.transport) == "udp"))
    tcp_hosts = Enum.filter(host_locals, &(String.downcase(&1.transport) == "tcp"))
    relay_only? = Listener.relay_only?(listener)

    udp_ok? = Enum.all?(udp_hosts, &MapSet.member?(expected_udp_keys, candidate_key(&1)))

    tcp_ok? =
      tcp_hosts == [] or Enum.all?(tcp_hosts, &MapSet.member?(expected_tcp_keys, candidate_key(&1)))

    cond do
      relay_only? and host_locals == [] ->
        :ok

      host_locals == [] and expected_udp != [] ->
        {:error, :local_candidate_mismatch}

      udp_ok? and tcp_ok? ->
        :ok

      true ->
        {:error, :local_candidate_mismatch}
    end
  end

  defp verify_srflx_locals(listener, config) do
    if Listener.stun_servers(listener) == [] do
      :ok
    else
      hosts_by_foundation =
        Map.new(Enum.filter(config.local_candidates, &(&1.type == "host")), &{&1.foundation, &1})

      srflx_ok? =
        config.local_candidates
        |> Enum.filter(&(&1.type == "srflx"))
        |> Enum.all?(fn srflx ->
          case Map.get(hosts_by_foundation, srflx.foundation) do
            nil ->
              false

            host ->
              srflx.priority < host.priority and srflx.rest =~ "raddr" and srflx.rest =~ "rport"
          end
        end)

      if srflx_ok?, do: :ok, else: {:error, :local_candidate_mismatch}
    end
  end

  defp verify_relay_locals(listener, config) do
    turn_servers = Listener.turn_servers(listener)
    relay_locals = Enum.filter(config.local_candidates, &(&1.type == "relay"))

    cond do
      turn_servers == [] ->
        :ok

      Listener.relay_only?(listener) and relay_locals == [] ->
        {:error, :local_candidate_mismatch}

      true ->
        host_max =
          config.local_candidates
          |> Enum.filter(&(&1.type in ["host", "srflx"]))
          |> Enum.map(& &1.priority)
          |> Enum.max(fn -> 0 end)

        relay_ok? =
          Enum.all?(relay_locals, fn relay ->
            relay.foundation not in [nil, ""] and
              (host_max == 0 or relay.priority < host_max)
          end)

        if relay_ok?, do: :ok, else: {:error, :local_candidate_mismatch}
    end
  end
end
