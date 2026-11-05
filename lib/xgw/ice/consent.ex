defmodule XGW.ICE.Consent do
  @moduledoc """
  Keeps an already-selected ICE path "alive" (consent freshness, RFC 7675).

  ## Why consent matters

  After ICE nominates a pair, the path can still die silently: a NAT binding
  may expire, a firewall may close UDP state, or a peer may disappear. WebRTC
  therefore periodically sends lightweight STUN Binding probes. If no fresh
  consent is observed within a timeout, the connection should be torn down
  instead of sending media into a black hole.

  Helpers here build outbound consent Binding requests and track
  `last_consent_at` for both ICE-lite and ICE-full agents.

  ## RFCs

  * RFC 7675 -- ICE consent freshness
  * RFC 8489 -- STUN Binding used as consent probes
  * RFC 8445 -- USERNAME / MESSAGE-INTEGRITY for Binding requests
  """

  alias XMediaLib.Stun

  @typedoc "ICE agent map with consent fields (lite or full)."
  @type ice :: map()

  @doc """
  Builds an outbound STUN Binding request for consent freshness.

  Uses USERNAME `remote:local` (sender perspective per RFC 8445 pt.7.2.2) and
  MESSAGE-INTEGRITY with the remote `ice-pwd`.
  No ICE role attributes.
  """
  @spec binding_request(ice()) :: binary()
  def binding_request(%{remote_ice_ufrag: remote, ice_ufrag: local} = ice)
      when is_binary(remote) and is_binary(local) do
    pwd = Map.get(ice, :remote_ice_pwd) || Map.fetch!(ice, :ice_pwd)

    %Stun{
      class: :request,
      method: :binding,
      transactionid: :rand.uniform(1_000_000_000_000),
      integrity: true,
      key: pwd,
      fingerprint: true,
      attrs: %{username: "#{remote}:#{local}"}
    }
    |> Stun.encode()
  end

  @doc """
  Records consent freshness at monotonic time `now_ms`.

  ## Examples

      iex> XGW.ICE.Consent.refresh(%{last_consent_at: nil}, 1234)
      %{last_consent_at: 1234}
  """
  @spec refresh(ice(), integer()) :: ice()
  def refresh(ice, now_ms) when is_integer(now_ms) do
    Map.put(ice, :last_consent_at, now_ms)
  end

  @doc """
  Returns true when consent has expired (no refresh within `timeout_ms`).

  ## Examples

      iex> XGW.ICE.Consent.expired?(%{last_consent_at: nil}, 1000, 500)
      false

      iex> XGW.ICE.Consent.expired?(%{last_consent_at: 100}, 700, 500)
      true

      iex> XGW.ICE.Consent.expired?(%{last_consent_at: 100}, 400, 500)
      false
  """
  @spec expired?(ice(), integer(), non_neg_integer()) :: boolean()
  def expired?(%{last_consent_at: nil}, _now_ms, _timeout_ms), do: false

  def expired?(%{last_consent_at: ts}, now_ms, timeout_ms)
      when is_integer(ts) and is_integer(now_ms) and is_integer(timeout_ms) do
    now_ms - ts > timeout_ms
  end
end
