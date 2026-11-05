defmodule XGW.ICE.Checklist do
  @moduledoc """
  Forms, sorts, and advances ICE candidate **pairs** through check states.

  ## Why a checklist exists

  Each local candidate can be paired with each remote candidate that shares
  component id, transport, and address family. ICE tries those pairs in
  priority order with STUN Binding checks. This module is the pure state
  machine for that list: build/extend pairs, mark in-progress/succeeded/failed,
  nominate, and pick the next check.

  States follow RFC 8445 (`:waiting`, `:in_progress`, `:succeeded`, `:failed`,
  `:frozen`).

  ponytail: serial check queue (one `:in_progress` pair at a time); upgrade path:
  parallel checks per foundation with per-pair RTO timers.

  ## RFCs

  * RFC 8445 -- candidate pair formation, priority, checklist states, nomination
  """

  alias XGW.ICE
  alias XMediaLib.SDP.Candidate

  @initial_rto_ms 500
  @max_retransmits 7

  @typedoc "Checklist pair state (`:waiting` | `:in_progress` | `:succeeded` | `:failed` | `:frozen`)."
  @type pair_state :: :waiting | :in_progress | :succeeded | :failed | :frozen

  @typedoc """
  One local x remote candidate pair on the checklist.

  ## Fields

  * `:local` / `:remote` - ICE candidates forming the pair
  * `:priority` - RFC 8445 pair priority
  * `:state` - checklist state
  * `:nominated?` - true after USE-CANDIDATE / nomination
  * `:transaction_id` - STUN transaction for the in-flight check
  * `:rto_ms` / `:retransmit_count` / `:last_sent_ms` - retransmit timer state
  """
  @type pair :: %{
          local: Candidate.t(),
          remote: Candidate.t(),
          priority: non_neg_integer(),
          state: pair_state(),
          nominated?: boolean(),
          transaction_id: non_neg_integer() | nil,
          rto_ms: non_neg_integer(),
          retransmit_count: non_neg_integer(),
          last_sent_ms: integer() | nil
        }

  @doc """
  Builds UDP component-1 pairs from local and remote candidate lists.
  """
  @spec build([Candidate.t()], [Candidate.t()], ICE.role()) :: [pair()]
  def build(locals, remotes, role) do
    for local <- locals,
        remote <- remotes,
        local.component_id == remote.component_id,
        same_transport?(local, remote),
        ICE.same_address_family?(local, remote) do
      %{
        local: local,
        remote: remote,
        priority: ICE.pair_priority(role, local.priority, remote.priority),
        state: :waiting,
        nominated?: false,
        transaction_id: nil,
        rto_ms: @initial_rto_ms,
        retransmit_count: 0,
        last_sent_ms: nil
      }
    end
    |> sort()
    |> prune_redundant()
  end

  @doc """
  Extends an existing checklist with pairs for new locals/remotes without resetting
  in-progress or succeeded pair state (trickle during checking).
  """
  @spec extend([pair()], [Candidate.t()], [Candidate.t()], ICE.role()) :: [pair()]
  def extend(existing, locals, remotes, role) when is_list(existing) do
    fresh = build(locals, remotes, role)

    existing_by_key =
      Map.new(existing, fn p -> {{p.local.foundation, p.remote.foundation}, p} end)

    merged =
      Enum.map(fresh, fn p ->
        case Map.get(existing_by_key, {p.local.foundation, p.remote.foundation}) do
          nil ->
            p

          old ->
            %{
              p
              | state: old.state,
                nominated?: old.nominated?,
                transaction_id: old.transaction_id,
                rto_ms: old.rto_ms,
                retransmit_count: old.retransmit_count,
                last_sent_ms: old.last_sent_ms
            }
        end
      end)

    sort(merged) |> prune_redundant()
  end

  @doc """
  Sorts pairs descending by priority.

  ## Examples

      iex> pairs = [%{priority: 1}, %{priority: 9}, %{priority: 5}]
      iex> Enum.map(XGW.ICE.Checklist.sort(pairs), & &1.priority)
      [9, 5, 1]
  """
  @spec sort([pair()]) :: [pair()]
  def sort(pairs), do: Enum.sort_by(pairs, & &1.priority, :desc)

  @doc """
  Drops lower-priority pairs sharing the same local and remote foundation.

  ## Examples

      iex> a = %{local: %{foundation: "1"}, remote: %{foundation: "a"}, priority: 10}
      iex> b = %{local: %{foundation: "1"}, remote: %{foundation: "a"}, priority: 1}
      iex> c = %{local: %{foundation: "2"}, remote: %{foundation: "a"}, priority: 5}
      iex> length(XGW.ICE.Checklist.prune_redundant([a, b, c]))
      2
  """
  @spec prune_redundant([pair()]) :: [pair()]
  def prune_redundant(pairs) do
    pairs
    |> Enum.uniq_by(fn p -> {p.local.foundation, p.remote.foundation} end)
  end

  @doc """
  Marks a pair `:in_progress` with a new transaction id.
  """
  @spec mark_in_progress([pair()], pair(), non_neg_integer(), integer()) :: [pair()]
  def mark_in_progress(pairs, target, transaction_id, now_ms) do
    Enum.map(pairs, fn p ->
      if same_pair?(p, target) do
        %{
          p
          | state: :in_progress,
            transaction_id: transaction_id,
            last_sent_ms: now_ms,
            retransmit_count: p.retransmit_count + 1
        }
      else
        p
      end
    end)
  end

  @doc """
  Marks the pair matching `transaction_id` as succeeded.
  """
  @spec mark_succeeded([pair()], non_neg_integer()) :: [pair()]
  def mark_succeeded(pairs, transaction_id) do
    Enum.map(pairs, fn
      %{transaction_id: ^transaction_id} = p -> %{p | state: :succeeded}
      p -> p
    end)
  end

  @doc """
  Marks a pair failed (RTO exhausted).
  """
  @spec mark_failed([pair()], pair()) :: [pair()]
  def mark_failed(pairs, target) do
    Enum.map(pairs, fn p ->
      if same_pair?(p, target), do: %{p | state: :failed}, else: p
    end)
  end

  @doc """
  Schedules retransmit: doubles RTO unless max retransmits reached (-> failed).
  """
  @spec schedule_retransmit([pair()], pair()) :: [pair()]
  def schedule_retransmit(pairs, target) do
    Enum.map(pairs, fn p ->
      if same_pair?(p, target) do
        if p.retransmit_count >= @max_retransmits do
          %{p | state: :failed}
        else
          %{p | rto_ms: p.rto_ms * 2, last_sent_ms: nil}
        end
      else
        p
      end
    end)
  end

  @doc """
  Returns true when all pairs are failed.

  ## Examples

      iex> XGW.ICE.Checklist.all_failed?([])
      false

      iex> XGW.ICE.Checklist.all_failed?([%{state: :failed}, %{state: :failed}])
      true
  """
  @spec all_failed?([pair()]) :: boolean()
  def all_failed?(pairs), do: pairs != [] and Enum.all?(pairs, &(&1.state == :failed))

  @doc """
  Returns true when a nominated pair has succeeded.

  ## Examples

      iex> XGW.ICE.Checklist.nominated_succeeded?([
      ...>   %{nominated?: true, state: :succeeded}
      ...> ])
      true
  """
  @spec nominated_succeeded?([pair()]) :: boolean()
  def nominated_succeeded?(pairs) do
    Enum.any?(pairs, &(&1.nominated? and &1.state == :succeeded))
  end

  @doc """
  Marks the pair matching remote/local as nominated.
  """
  @spec nominate([pair()], Candidate.t(), Candidate.t()) :: [pair()]
  def nominate(pairs, local, remote) do
    Enum.map(pairs, fn p ->
      if p.local.foundation == local.foundation and p.remote.foundation == remote.foundation do
        %{p | nominated?: true, state: :succeeded}
      else
        p
      end
    end)
  end

  @doc """
  Marks a specific pair succeeded by identity.
  """
  @spec mark_pair_succeeded([pair()], pair()) :: [pair()]
  def mark_pair_succeeded(pairs, target) do
    Enum.map(pairs, fn p ->
      if same_pair?(p, target), do: %{p | state: :succeeded}, else: p
    end)
  end

  @doc """
  Finds pair by outbound transaction id.
  """
  @spec find_by_transaction([pair()], non_neg_integer()) :: pair() | nil
  def find_by_transaction(pairs, transaction_id) do
    Enum.find(pairs, &(&1.transaction_id == transaction_id))
  end

  @doc """
  Finds pair matching remote endpoint and optional local candidate.
  """
  @spec find_by_remote([pair()], ICE.endpoint(), Candidate.t() | nil) :: pair() | nil
  def find_by_remote(pairs, {ip, port}, local \\ nil) do
    Enum.find(pairs, fn p ->
      {rip, rport} = ICE.endpoint(p.remote)
      local_ok? = is_nil(local) or p.local.foundation == local.foundation
      rip == ip and rport == port and local_ok?
    end)
  end

  @doc """
  Returns the next pair needing an outbound check, or nil.

  Prefers an already `:in_progress` pair (serial queue) over the next `:waiting`.

  ## Examples

      iex> waiting = %{state: :waiting}
      iex> busy = %{state: :in_progress}
      iex> XGW.ICE.Checklist.next_check([waiting, busy])
      %{state: :in_progress}
  """
  @spec next_check([pair()]) :: pair() | nil
  def next_check(pairs) do
    case Enum.find(pairs, &(&1.state == :in_progress)) do
      nil ->
        Enum.find(pairs, &(&1.state == :waiting))

      in_progress ->
        in_progress
    end
  end

  @doc """
  Returns true when RTO has expired for an in-progress pair.

  ## Examples

      iex> XGW.ICE.Checklist.rto_expired?(
      ...>   %{state: :in_progress, last_sent_ms: 0, rto_ms: 500},
      ...>   500
      ...> )
      true

      iex> XGW.ICE.Checklist.rto_expired?(%{state: :waiting}, 1000)
      false
  """
  @spec rto_expired?(pair(), integer()) :: boolean()
  def rto_expired?(%{state: :in_progress, last_sent_ms: ts, rto_ms: rto}, now_ms)
      when is_integer(ts) do
    now_ms - ts >= rto
  end

  def rto_expired?(_, _), do: false

  @doc """
  Returns true when two pairs share the same local and remote foundations.

  ## Examples

      iex> a = %{local: %{foundation: "1"}, remote: %{foundation: "x"}}
      iex> b = %{local: %{foundation: "1"}, remote: %{foundation: "x"}}
      iex> XGW.ICE.Checklist.same_pair?(a, b)
      true
  """
  @spec same_pair?(pair(), pair()) :: boolean()
  def same_pair?(a, b) do
    a.local.foundation == b.local.foundation and a.remote.foundation == b.remote.foundation
  end

  defp same_transport?(a, b) do
    String.downcase(a.transport) == String.downcase(b.transport)
  end
end
