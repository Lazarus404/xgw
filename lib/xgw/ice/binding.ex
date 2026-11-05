defmodule XGW.ICE.Binding do
  @moduledoc """
  Builds and validates STUN Binding messages used as ICE connectivity checks.

  ## Plain language

  **STUN** (Session Traversal Utilities for NAT) is a small request/response
  protocol often carried in UDP. ICE uses STUN **Binding** requests as
  "can you hear me on this address?" probes. Successful checks prove a
  candidate pair works; attributes such as `ICE-CONTROLLING` /
  `ICE-CONTROLLED` and `USE-CANDIDATE` carry nomination and role info.

  Integrity uses the SDP `ice-pwd` as a MESSAGE-INTEGRITY key. This module is
  shared by ICE-lite (mostly inbound responses) and ICE-full (outbound checks
  plus responses).

  ## RFCs

  * RFC 8489 -- STUN Binding request/response, MESSAGE-INTEGRITY, FINGERPRINT
  * RFC 8445 -- ICE connectivity checks, USERNAME form, role attrs, USE-CANDIDATE
  """

  alias XMediaLib.Stun

  @typedoc """
  Credential map for STUN encode/decode during ICE checks.

  ## Fields

  * `:ice_ufrag` / `:ice_pwd` - local ICE credentials from SDP
  * `:remote_ice_ufrag` / `:remote_ice_pwd` - remote credentials (optional until known)
  * `:tiebreaker` - ICE role conflict tie-breaker
  * `:role` - `:controlling` or `:controlled`
  """
  @type creds :: %{
          optional(:ice_ufrag) => String.t(),
          optional(:ice_pwd) => String.t(),
          optional(:remote_ice_ufrag) => String.t() | nil,
          optional(:remote_ice_pwd) => String.t() | nil,
          optional(:tiebreaker) => binary(),
          optional(:role) => :controlling | :controlled
        }

  @doc """
  Decodes STUN Binding packets.

  Tries local `ice_pwd` first (ICE-lite inbound checks), then `remote_ice_pwd`
  when set (peer-signed consent / full-ICE responses).
  """
  @spec decode(binary(), creds()) :: {:ok, Stun.t()} | {:error, term()}
  def decode(data, %{ice_pwd: local} = creds) do
    # Prefer local ice-pwd first: ICE-lite inbound checks are signed with it.
    # Remote-first caused a MESSAGE-INTEGRITY miss log on every healthy check.
    passwords =
      case Map.get(creds, :remote_ice_pwd) do
        pwd when is_binary(pwd) and pwd != "" and pwd != local -> [local, pwd]
        _ -> [local]
      end

    Enum.reduce_while(passwords, {:error, :integrity}, fn pwd, _acc ->
      case Stun.decode(data, pwd) do
        {:ok, stun} -> {:halt, {:ok, stun}}
        _ -> {:cont, {:error, :integrity}}
      end
    end)
  end

  @doc """
  Returns true when USERNAME matches RFC 8445 inbound checks.

  The sender sets USERNAME to `remote_candidate_ufrag:local_candidate_ufrag`,
  which at the receiver is `ice_ufrag:remote_ice_ufrag`.
  """
  @spec valid_username?(Stun.t(), creds()) :: boolean()
  def valid_username?(_req, %{remote_ice_ufrag: nil}), do: true

  def valid_username?(%Stun{attrs: attrs}, creds) do
    case Map.get(attrs, :username) do
      nil ->
        true

      username when is_binary(username) ->
        username == "#{creds.ice_ufrag}:#{creds.remote_ice_ufrag}"

      _ ->
        false
    end
  end

  @doc """
  Returns true when the request is an ICE connectivity check (role attrs present).
  """
  @spec connectivity_check?(Stun.t()) :: boolean()
  def connectivity_check?(%Stun{attrs: attrs}) do
    Map.has_key?(attrs, :ice_controlling) or Map.has_key?(attrs, :ice_controlled)
  end

  @doc """
  Returns true when the request includes USE-CANDIDATE (nomination).
  """
  @spec use_candidate?(Stun.t()) :: boolean()
  def use_candidate?(%Stun{attrs: attrs}) do
    Map.has_key?(attrs, :use_candidate)
  end

  @doc """
  Builds a Binding success response for an inbound request.
  """
  @spec build_success(Stun.t(), {:inet.ip_address(), :inet.port_number()}, creds()) ::
          binary()
  def build_success(req, {ip, port}, creds) do
    attrs =
      if connectivity_check?(req) do
        role_attr =
          case Map.get(creds, :role, :controlled) do
            :controlling -> {:ice_controlling, creds.tiebreaker}
            :controlled -> {:ice_controlled, creds.tiebreaker}
          end

        Map.merge(%{xor_mapped_address: {ip, port}}, Map.new([role_attr]))
      else
        %{xor_mapped_address: {ip, port}}
      end

    %Stun{
      class: :success,
      method: :binding,
      transactionid: req.transactionid,
      integrity: true,
      key: creds.ice_pwd,
      fingerprint: true,
      attrs: attrs
    }
    |> Stun.encode()
  end

  @doc """
  Builds an outbound ICE connectivity check Binding request.

  USERNAME is `remote:local` (peer ufrag first); MESSAGE-INTEGRITY uses the
  remote pwd (RFC 8445 pt.7.2.2).
  """
  @spec build_check_request(creds(), non_neg_integer(), keyword()) :: binary()
  def build_check_request(creds, priority, opts \\ []) do
    remote = creds.remote_ice_ufrag
    local = creds.ice_ufrag
    pwd = creds.remote_ice_pwd || creds.ice_pwd

    role = Map.get(creds, :role, :controlled)

    role_attr =
      case role do
        :controlling -> {:ice_controlling, creds.tiebreaker}
        :controlled -> {:ice_controlled, creds.tiebreaker}
      end

    attrs =
      %{
        username: "#{remote}:#{local}",
        priority: <<priority::32>>
      }
      |> Map.merge(Map.new([role_attr]))
      |> maybe_put_use_candidate(Keyword.get(opts, :use_candidate, false))

    transactionid = Keyword.get(opts, :transactionid, :rand.uniform(0xFFFFFFFFFFFF))

    %Stun{
      class: :request,
      method: :binding,
      transactionid: transactionid,
      integrity: true,
      key: pwd,
      fingerprint: true,
      attrs: attrs
    }
    |> Stun.encode()
  end

  defp maybe_put_use_candidate(attrs, true), do: Map.put(attrs, :use_candidate, <<>>)
  defp maybe_put_use_candidate(attrs, _), do: attrs
end
