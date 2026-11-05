defmodule XGW.ICE.Lite do
  @moduledoc """
  ICE-lite agent: answer inbound STUN checks in the controlled role.

  ## Lite vs full

  Many media servers sit on a public IP and never need to punch outbound NAT
  holes themselves. **ICE-lite** (RFC 8445) is that mode: the agent publishes
  host candidates, verifies MESSAGE-INTEGRITY with its local `ice-pwd`,
  optionally checks USERNAME, merges trickle remote candidates, and responds
  to Binding requests. Connectivity is declared when inbound checks include
  ICE role attributes (and nomination when required).

  Use `ice_lite: false` on the Peer for `XGW.ICE.Full` instead.

  ## RFCs

  * RFC 8445 -- ICE-lite (controlled role, inbound checks only)
  * RFC 8489 -- STUN Binding responses
  * RFC 7675 -- consent freshness
  """

  require Logger

  alias XGW.ICE
  alias XGW.ICE.Binding
  alias XMediaLib.Stun
  alias XMediaLib.SDP.Candidate

  @ice_chars ~c"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

  @typedoc "Remote UDP endpoint `{ip, port}`."
  @type from :: ICE.endpoint()

  @typedoc """
  ICE-lite agent state.

  * `ice_ufrag` / `ice_pwd` - local credentials from the answer
  * `remote_ice_ufrag` - remote ufrag from the offer (username validation)
  * `remote_ice_pwd` - remote pwd from the offer (outbound STUN integrity)
  * `remote_candidates` - merged trickle + SDP remote candidates (priority order)
  * `remote_candidates_eoc?` - true after end-of-candidates
  * `last_consent_at` - monotonic ms of last consent refresh (RFC 7675)
  * `connected?` - true after first ICE connectivity check
  * `selected` - validated remote `{ip, port}` pair
  """
  @type t :: %{
          ice_ufrag: String.t(),
          ice_pwd: String.t(),
          ice_tiebreaker: binary(),
          remote_ice_ufrag: String.t() | nil,
          remote_ice_pwd: String.t() | nil,
          bundle_mids: [String.t()],
          remote_candidates: [Candidate.t()],
          remote_candidates_eoc?: boolean(),
          last_consent_at: integer() | nil,
          connected?: boolean(),
          selected: from() | nil
        }

  @doc """
  Builds ICE-lite state from `XGW.Descriptions` config.
  """
  @spec from_config(map()) :: t()
  def from_config(%{ice: %{local_ufrag: ufrag, local_pwd: pwd, remote_ufrag: remote_ufrag}} = config) do
    %{
      ice_ufrag: ufrag,
      ice_pwd: pwd,
      ice_tiebreaker: :crypto.strong_rand_bytes(8),
      remote_ice_ufrag: remote_ufrag,
      remote_ice_pwd: Map.get(config.ice, :remote_pwd),
      bundle_mids: Map.get(config, :bundle_mids, []),
      remote_candidates: [],
      remote_candidates_eoc?: false,
      last_consent_at: nil,
      connected?: false,
      selected: nil
    }
  end

  @doc """
  Builds ICE-lite state with explicit credentials (tests and callers without SDP).
  """
  @spec new(keyword()) :: t()
  def new(opts) when is_list(opts) do
    %{
      ice_ufrag: Keyword.get(opts, :ice_ufrag, random_ice_string(4)),
      ice_pwd: Keyword.get(opts, :ice_pwd, random_ice_string(22)),
      ice_tiebreaker: Keyword.get(opts, :ice_tiebreaker, :crypto.strong_rand_bytes(8)),
      remote_ice_ufrag: Keyword.get(opts, :remote_ice_ufrag),
      remote_ice_pwd: Keyword.get(opts, :remote_ice_pwd),
      bundle_mids: Keyword.get(opts, :bundle_mids, []),
      remote_candidates: [],
      remote_candidates_eoc?: false,
      last_consent_at: nil,
      connected?: false,
      selected: nil
    }
  end

  @doc """
  Seeds ICE-lite state with remote candidates from the initial offer SDP.
  """
  @spec seed_remote_candidates(t(), [Candidate.t()]) :: t()
  def seed_remote_candidates(ice, candidates) when is_list(candidates) do
    %{ice | remote_candidates: ICE.merge_remote(ice.remote_candidates, candidates)}
  end

  @doc """
  Merges remote candidates (delegates to `XGW.ICE.merge_remote/2`).
  """
  @spec merge_remote_candidates([Candidate.t()], [Candidate.t()]) :: [Candidate.t()]
  defdelegate merge_remote_candidates(existing, incoming), to: ICE, as: :merge_remote

  @doc """
  Adds a trickle remote candidate or records end-of-candidates.
  """
  @spec add_remote_candidate(t(), map() | Candidate.t()) :: {:ok, t()} | {:error, term()}
  def add_remote_candidate(ice, %Candidate{} = cand) do
    add_remote_candidate(ice, %{candidate: cand})
  end

  def add_remote_candidate(ice, info) when is_map(info) do
    ice =
      if Map.get(info, :end_of_candidates) do
        %{ice | remote_candidates_eoc?: true}
      else
        ice
      end

    cond do
      Map.has_key?(info, :candidate) ->
        with {:ok, cand} <- ICE.coerce_candidate(Map.fetch!(info, :candidate)),
             :ok <- ICE.validate_mid(info, ice.bundle_mids) do
          merged = ICE.merge_remote(ice.remote_candidates, [cand])
          {:ok, %{ice | remote_candidates: merged}}
        end

      Map.get(info, :end_of_candidates) ->
        {:ok, ice}

      true ->
        {:error, :missing_candidate}
    end
  end

  @doc """
  Returns `{ip, port}` for a parsed candidate (delegates to `XGW.ICE.endpoint/1`).
  """
  @spec endpoint(Candidate.t()) :: from()
  defdelegate endpoint(cand), to: ICE

  @doc """
  Handles one STUN datagram from `from`.

  Returns `{:reply, wire, state}` for a binding response, optionally
  `{:connected, wire, state}` when the first ICE connectivity check succeeds,
  or `{:consent, state}` for an inbound Binding success (RFC 7675).
  """
  @spec handle_binding(binary(), from(), t()) ::
          {:reply, binary(), t()}
          | {:connected, binary(), t()}
          | {:consent, t()}
          | {:ignore, t()}
  def handle_binding(data, from, state) do
    creds = lite_creds(state)

    case Binding.decode(data, creds) do
      {:ok, %Stun{class: :success, method: :binding}} ->
        {:consent, state}

      {:ok, %Stun{class: :request, method: :binding} = req} ->
        if Binding.valid_username?(req, creds) do
          reply = Binding.build_success(req, from, creds)
          check? = Binding.connectivity_check?(req)
          use_cand? = Binding.use_candidate?(req)

          # Keep the first selected pair unless Chrome nominates another (USE-CANDIDATE).
          state =
            cond do
              use_cand? ->
                %{state | selected: from}

              not state.connected? ->
                %{state | selected: from}

              true ->
                state
            end

          if state.connected? or not check? do
            {:reply, reply, state}
          else
            {:connected, reply, %{state | connected?: true, selected: from}}
          end
        else
          Logger.debug(
            "ice-lite username mismatch got=#{inspect(Map.get(req.attrs, :username))} want=#{creds.ice_ufrag}:#{creds.remote_ice_ufrag}"
          )

          {:ignore, state}
        end

      _ ->
        {:ignore, state}
    end
  end

  defp lite_creds(state) do
    %{
      ice_ufrag: state.ice_ufrag,
      ice_pwd: state.ice_pwd,
      remote_ice_ufrag: state.remote_ice_ufrag,
      remote_ice_pwd: state.remote_ice_pwd,
      tiebreaker: state.ice_tiebreaker,
      role: :controlled
    }
  end

  defp random_ice_string(n) do
    len = length(@ice_chars)

    for <<b <- :crypto.strong_rand_bytes(n)>>, into: <<>> do
      <<Enum.at(@ice_chars, rem(b, len))>>
    end
  end
end
