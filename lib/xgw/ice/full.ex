defmodule XGW.ICE.Full do
  @moduledoc """
  Full ICE agent: gather candidates, run the checklist, nominate a pair.

  ## When to use full ICE

  **ICE-lite** only answers inbound STUN checks (typical for a public server
  with a known address). **Full ICE** also gathers local candidates, forms
  pairs, and sends outbound connectivity checks -- required when the gateway
  sits behind NAT or needs TURN relay paths itself.

  Phase transitions:

  ```text
  :gathering -> :checking -> :connected
  ```

  Outbound and inbound STUN checks, nomination (`USE-CANDIDATE`), and trickle
  candidate merges all live here. Pure helpers stay in `XGW.ICE` /
  `XGW.ICE.Checklist`; this module owns agent state updates used by `XGW.Peer`.

  ## RFCs

  * RFC 8445 -- full ICE agent (gather, checklist, checks, nomination, phases)
  * RFC 8489 -- STUN Binding for connectivity checks
  * RFC 7675 -- consent freshness after nomination
  """

  alias XGW.ICE
  alias XGW.ICE.{Binding, Checklist, Consent}
  alias XMediaLib.Stun
  alias XMediaLib.SDP.Candidate

  @check_ta_ms 50

  @typedoc "Remote UDP endpoint `{ip, port}`."
  @type from :: ICE.endpoint()

  @typedoc """
  Full ICE agent state.
  """
  @type t :: %{
          phase: ICE.ice_phase(),
          role: ICE.role(),
          tiebreaker: binary(),
          ice_ufrag: String.t() | nil,
          ice_pwd: String.t() | nil,
          remote_ice_ufrag: String.t() | nil,
          remote_ice_pwd: String.t() | nil,
          bundle_mids: [String.t()],
          local_candidates: [Candidate.t()],
          remote_candidates: [Candidate.t()],
          remote_candidates_eoc?: boolean(),
          checklist: [Checklist.pair()],
          nominated_pair: Checklist.pair() | nil,
          selected: from() | nil,
          pending_triggered: Checklist.pair() | nil,
          last_consent_at: integer() | nil
        }

  @typedoc """
  Result of handling inbound STUN while checking or connected.

  Includes consent refresh (`:consent`) and nomination (`:connected`).
  """
  @type stun_result ::
          {:ignore, t()}
          | {:reply, binary(), t()}
          | {:send, binary(), from(), t()}
          | {:connected, binary(), t(), from()}
          | {:consent, t()}

  @doc """
  Builds an empty full ICE agent (before `apply_descriptions`).
  """
  @spec new(keyword()) :: t()
  def new(_opts \\ []) do
    base_state()
  end

  @doc """
  Builds full ICE state from `XGW.Descriptions` config after negotiation.
  """
  @spec from_config(map()) :: {:ok, t()} | {:error, :unsupported_setup}
  def from_config(%{ice: ice} = config) do
    with {:ok, role} <- ICE.role(ice.remote_setup, ice.local_setup) do
      {:ok,
       base_state()
       |> Map.merge(%{
         role: role,
         tiebreaker: :crypto.strong_rand_bytes(8),
         ice_ufrag: ice.local_ufrag,
         ice_pwd: ice.local_pwd,
         remote_ice_ufrag: ice.remote_ufrag,
         remote_ice_pwd: ice.remote_pwd,
         bundle_mids: Map.get(config, :bundle_mids, [])
       })}
    end
  end

  @doc """
  Seeds local candidates from the local answer SDP.
  """
  @spec seed_local_candidates(t(), [Candidate.t()]) :: t()
  def seed_local_candidates(full, candidates) when is_list(candidates) do
    %{full | local_candidates: ICE.merge_remote(full.local_candidates, candidates)}
  end

  @doc """
  Merges one local candidate (host, srflx, or relay trickle) into the agent.
  """
  @spec add_local_candidate(t(), Candidate.t()) :: {:ok, t()}
  def add_local_candidate(full, %Candidate{} = cand) do
    {:ok, %{full | local_candidates: ICE.merge_remote(full.local_candidates, [cand])}}
  end

  @doc """
  Seeds remote candidates from the initial offer SDP.
  """
  @spec seed_remote_candidates(t(), [Candidate.t()]) :: t()
  def seed_remote_candidates(full, candidates) when is_list(candidates) do
    %{full | remote_candidates: ICE.merge_remote(full.remote_candidates, candidates)}
  end

  @doc """
  Adds a trickle remote candidate or records end-of-candidates.
  """
  @spec add_remote_candidate(t(), map() | Candidate.t()) :: {:ok, t()} | {:error, term()}
  def add_remote_candidate(full, %Candidate{} = cand) do
    add_remote_candidate(full, %{candidate: cand})
  end

  def add_remote_candidate(full, info) when is_map(info) do
    full =
      if Map.get(info, :end_of_candidates) do
        %{full | remote_candidates_eoc?: true}
      else
        full
      end

    cond do
      Map.has_key?(info, :candidate) ->
        with {:ok, cand} <- ICE.coerce_candidate(Map.fetch!(info, :candidate)),
             :ok <- ICE.validate_mid(info, full.bundle_mids) do
          merged = ICE.merge_remote(full.remote_candidates, [cand])
          full = %{full | remote_candidates: merged}
          {:ok, rebuild_checklist(full)}
        end

      Map.get(info, :end_of_candidates) ->
        {:ok, full}

      true ->
        {:error, :missing_candidate}
    end
  end

  @doc """
  Returns checklist inputs for pair formation.
  """
  @spec checklist_inputs(t()) :: %{local: [Candidate.t()], remote: [Candidate.t()]}
  def checklist_inputs(%{local_candidates: local, remote_candidates: remote}) do
    %{local: local, remote: remote}
  end

  @doc """
  Returns true when at least one local and one remote candidate exist.
  """
  @spec ready_for_checks?(t()) :: boolean()
  def ready_for_checks?(full) do
    full.local_candidates != [] and full.remote_candidates != []
  end

  @doc """
  Builds the checklist and moves phase to `:checking`.
  """
  @spec start_checking(t()) :: t()
  def start_checking(full) do
    if ready_for_checks?(full) do
      checklist = Checklist.build(full.local_candidates, full.remote_candidates, full.role)

      %{full | phase: :checking, checklist: checklist}
    else
      full
    end
  end

  @doc """
  Rebuilds the checklist after new local candidates arrive (srflx/relay trickle).
  """
  @spec extend_locals(t(), [Candidate.t()]) :: t()
  def extend_locals(full, new_locals) when is_list(new_locals) do
    full = %{full | local_candidates: ICE.merge_remote(full.local_candidates, new_locals)}

    if full.phase in [:checking, :gathering] and ready_for_checks?(full) do
      checklist = merge_checklist(full)
      %{full | phase: :checking, checklist: checklist}
    else
      full
    end
  end

  @doc """
  Returns the ICE phase.
  """
  @spec phase(t()) :: ICE.ice_phase()
  def phase(%{phase: phase}), do: phase

  @doc """
  Checklist tick interval in milliseconds (Ta).
  """
  @spec check_ta_ms() :: pos_integer()
  def check_ta_ms, do: @check_ta_ms

  @doc """
  Processes one checklist tick; may return an outbound STUN check to send.
  """
  @spec tick(t(), integer()) :: {:noop, t()} | {:send, binary(), from(), t(), non_neg_integer()}
  def tick(%{phase: :checking} = full, now_ms) do
    cond do
      full.pending_triggered ->
        send_triggered(full, full.pending_triggered, now_ms)

      match?(%{state: :in_progress}, Checklist.next_check(full.checklist)) ->
        in_progress = Checklist.next_check(full.checklist)

        if Checklist.rto_expired?(in_progress, now_ms) do
          checklist = Checklist.schedule_retransmit(full.checklist, in_progress)
          full = %{full | checklist: checklist}
          retry_or_next(full, in_progress, now_ms)
        else
          {:noop, full}
        end

      true ->
        case Checklist.next_check(full.checklist) do
          nil ->
            if Checklist.all_failed?(full.checklist) do
              {:noop, %{full | phase: :failed}}
            else
              {:noop, full}
            end

          pair ->
            send_check(full, pair, now_ms)
        end
    end
  end

  def tick(full, _now_ms), do: {:noop, full}

  @doc """
  Handles one STUN datagram (inbound checks and outbound responses).

  Options:

    * `:transport` - `:udp` (default) or `:tcp` (ICE-TCP path; peer-reflexive
      remotes inherit this so checklist pairs can form)
  """
  @spec handle_stun(binary(), from(), t(), keyword()) :: stun_result()
  def handle_stun(data, from, full, opts \\ []) do
    creds = full_creds(full)
    transport = transport_string(Keyword.get(opts, :transport, :udp))

    case Binding.decode(data, creds) do
      {:ok, %Stun{class: :success, method: :binding} = resp} ->
        if full.phase in [:connected, :completed] do
          {:consent, Consent.refresh(full, System.monotonic_time(:millisecond))}
        else
          handle_check_response(resp, full)
        end

      {:ok, %Stun{class: :request, method: :binding} = req} ->
        handle_inbound_request(req, from, full, creds, transport)

      _ ->
        {:ignore, full}
    end
  end

  defp transport_string(:tcp), do: "tcp"
  defp transport_string("tcp"), do: "tcp"
  defp transport_string("TCP"), do: "tcp"
  defp transport_string(_), do: "udp"
  @doc """
  Marks ICE processing complete after nomination (`:connected` -> `:completed`).
  """
  @spec mark_completed(t()) :: t()
  def mark_completed(%{phase: :connected} = full), do: %{full | phase: :completed}
  def mark_completed(full), do: full

  @doc """
  Resets checklist state for ICE restart (remote ufrag/pwd supplied by caller).
  """
  @spec ice_restart(t()) :: t()
  def ice_restart(full) do
    %{
      full
      | phase: :gathering,
        checklist: [],
        nominated_pair: nil,
        selected: nil,
        pending_triggered: nil,
        last_consent_at: nil
    }
  end

  defp handle_inbound_request(req, from, full, creds, transport) do
    if Binding.valid_username?(req, creds) do
      reply = Binding.build_success(req, from, creds)
      full = maybe_add_prflx_remote(full, from, req, transport)
      pair = Checklist.find_by_remote(full.checklist, from)

      checklist =
        if pair && Binding.connectivity_check?(req) do
          Checklist.mark_pair_succeeded(full.checklist, pair)
        else
          full.checklist
        end

      full = %{full | checklist: checklist, selected: from}

      cond do
        Binding.use_candidate?(req) and full.role == :controlled and pair ->
          checklist = Checklist.nominate(checklist, pair.local, pair.remote)
          full = %{full | checklist: checklist, nominated_pair: pair, phase: :connected, selected: from}
          {:connected, reply, full, from}

        Binding.connectivity_check?(req) and pair ->
          {:reply, reply, %{full | pending_triggered: pair}}

        true ->
          {:reply, reply, full}
      end
    else
      {:ignore, full}
    end
  end

  defp maybe_add_prflx_remote(full, from, req, transport) do
    if Checklist.find_by_remote(full.checklist, from) || not Binding.connectivity_check?(req) do
      full
    else
      prflx = ICE.prflx_candidate(from, priority_from_request(req), transport)
      remotes = ICE.merge_remote(full.remote_candidates, [prflx])
      full = %{full | remote_candidates: remotes}
      rebuild_checklist(full)
    end
  end

  defp priority_from_request(%Stun{attrs: attrs}) do
    case Map.get(attrs, :priority) do
      <<p::32>> -> p
      _ -> 1
    end
  end

  defp handle_check_response(%Stun{transactionid: tid}, full) do
    case Checklist.find_by_transaction(full.checklist, tid) do
      nil ->
        {:ignore, full}

      pair ->
        checklist = Checklist.mark_succeeded(full.checklist, tid)
        full = %{full | checklist: checklist}

        if full.role == :controlling and pair == hd(Checklist.sort(full.checklist)) do
          checklist = Checklist.nominate(checklist, pair.local, pair.remote)
          dest = ICE.endpoint(pair.remote)
          full = %{full | checklist: checklist, phase: :connected, selected: dest, nominated_pair: pair}
          {:connected, <<>>, full, dest}
        else
          {:ignore, full}
        end
    end
  end

  defp send_check(full, pair, now_ms) do
    transaction_id = :rand.uniform(0xFFFFFFFFFFFF)
    wire = build_outbound_check(full, pair, transaction_id)
    dest = check_destination(full, pair)
    checklist = Checklist.mark_in_progress(full.checklist, pair, transaction_id, now_ms)
    {:send, wire, dest, %{full | checklist: checklist}, transaction_id}
  end

  defp send_triggered(full, pair, now_ms) do
    transaction_id = :rand.uniform(0xFFFFFFFFFFFF)
    wire = build_outbound_check(full, pair, transaction_id)
    dest = ICE.endpoint(pair.remote)
    checklist = Checklist.mark_in_progress(full.checklist, pair, transaction_id, now_ms)
    {:send, wire, dest, %{full | checklist: checklist, pending_triggered: nil}, transaction_id}
  end

  defp retry_or_next(full, pair, now_ms) do
    case Enum.find(full.checklist, &Checklist.same_pair?(&1, pair)) do
      %{state: :failed} ->
        case Checklist.next_check(full.checklist) do
          nil -> {:noop, full}
          next -> send_check(full, next, now_ms)
        end

      updated ->
        send_check(full, updated, now_ms)
    end
  end

  defp build_outbound_check(full, pair, transaction_id) do
    use_candidate = full.role == :controlling and pair == hd(Checklist.sort(full.checklist))

    Binding.build_check_request(
      full_creds(full),
      pair.local.priority,
      transactionid: transaction_id,
      use_candidate: use_candidate
    )
  end

  defp check_destination(_full, %{local: %{type: "relay"}} = pair) do
    ICE.endpoint(pair.remote)
  end

  defp check_destination(_full, pair) do
    ICE.endpoint(pair.remote)
  end

  defp full_creds(full) do
    %{
      ice_ufrag: full.ice_ufrag,
      ice_pwd: full.ice_pwd,
      remote_ice_ufrag: full.remote_ice_ufrag,
      remote_ice_pwd: full.remote_ice_pwd,
      tiebreaker: full.tiebreaker,
      role: full.role
    }
  end

  defp base_state do
    %{
      phase: :gathering,
      role: :controlled,
      tiebreaker: :crypto.strong_rand_bytes(8),
      ice_ufrag: nil,
      ice_pwd: nil,
      remote_ice_ufrag: nil,
      remote_ice_pwd: nil,
      bundle_mids: [],
      local_candidates: [],
      remote_candidates: [],
      remote_candidates_eoc?: false,
      checklist: [],
      nominated_pair: nil,
      selected: nil,
      pending_triggered: nil,
      last_consent_at: nil
    }
  end

  defp rebuild_checklist(full) do
    if ready_for_checks?(full) do
      checklist = merge_checklist(full)
      %{full | phase: :checking, checklist: checklist}
    else
      full
    end
  end

  defp merge_checklist(%{phase: :checking, checklist: checklist} = full)
       when checklist != [] do
    Checklist.extend(
      checklist,
      full.local_candidates,
      full.remote_candidates,
      full.role
    )
  end

  defp merge_checklist(full) do
    Checklist.build(full.local_candidates, full.remote_candidates, full.role)
  end
end
