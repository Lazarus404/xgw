defmodule XGW.TURN.Client do
  @moduledoc """
  Client for TURN: allocate a relay address and send/receive through it.

  ## What TURN solves

  When direct UDP (and sometimes TCP) paths between two peers fail -- strict
  NATs, symmetric NAT combinations, corporate firewalls -- **TURN** (Traversal
  Using Relays around NAT) provides a relay on a publicly reachable server.
  Your peer sends to the relay; the relay forwards to the far side.

  This module speaks TURN over STUN (`XMediaLib.Stun`) without depending on the
  xturn server application. It covers Allocate / Refresh / Delete,
  CreatePermission, ChannelBind, Send Indication, and ChannelData -- enough
  for XGW to gather `relay` candidates and keep allocations alive.

  ## RFCs

  * RFC 8656 -- TURN (Allocate, Refresh, CreatePermission, ChannelBind, indications, ChannelData)
  * RFC 8489 -- STUN long-term credentials and MESSAGE-INTEGRITY
  * RFC 5766 -- ChannelData layout still used on the wire (channel number range)
  """

  alias XMediaLib.Stun

  @default_turn_port 3478
  @default_turn_ttl_s 86_400

  @typedoc """
  Active TURN allocation state for refresh and teardown.

  ## Fields

  * `:turn_server` - TURN server `{ip, port}` used for Allocate
  * `:relay` - allocated relay `{ip, port}` advertised as a local candidate
  * `:lifetime_s` - allocation lifetime from the success response
  * `:username` / `:realm` / `:nonce` - long-term credential challenge state
  * `:integrity_key` - MESSAGE-INTEGRITY key for subsequent TURN requests
  """
  @type allocation :: %{
          turn_server: {:inet.ip_address(), :inet.port_number()},
          relay: {:inet.ip_address(), :inet.port_number()},
          lifetime_s: pos_integer(),
          username: String.t(),
          realm: String.t(),
          nonce: String.t(),
          integrity_key: binary()
        }

  @doc """
  Parses a TURN server URI (`turn:host:port`) to `{ip, port}`.

  ## Examples

      iex> XGW.TURN.Client.parse_turn_server("turn:127.0.0.1:3478")
      {:ok, {{127, 0, 0, 1}, 3478}}

      iex> XGW.TURN.Client.parse_turn_server("turns:127.0.0.1:5349")
      {:error, :unsupported_turns}
  """
  @spec parse_turn_server(String.t()) ::
          {:ok, {:inet.ip_address(), :inet.port_number()}} | {:error, term()}
  def parse_turn_server("turn:" <> rest), do: parse_server_host(rest, :invalid_turn_server)
  def parse_turn_server("turns:" <> _), do: {:error, :unsupported_turns}
  def parse_turn_server(_), do: {:error, :invalid_turn_server}

  @doc """
  Parses host[:port] from a STUN/TURN URI body (after the scheme prefix).
  """
  @spec parse_server_host(String.t(), term()) ::
          {:ok, {:inet.ip_address(), :inet.port_number()}} | {:error, term()}
  def parse_server_host(rest, error \\ :invalid_server) do
    rest = String.trim_leading(rest, "//")

    case String.split(rest, ":", parts: 2) do
      [host, port_str] ->
        with {:ok, ip} <- resolve_host(host),
             {port, _} <- Integer.parse(port_str) do
          {:ok, {ip, port}}
        else
          _ -> {:error, error}
        end

      [host] ->
        case resolve_host(host) do
          {:ok, ip} -> {:ok, {ip, @default_turn_port}}
          err -> err
        end
    end
  end

  @doc """
  REST shared-secret credentials (`expiry:user_id` + Base64 HMAC-SHA1 password).

  Time-bound username form used by many hosted TURN providers. The password is
  not stored long-term; it is derived from `secret` and the username string.

  ## Examples

      iex> {user, pass} = XGW.TURN.Client.rest_credentials("alice", "s3cret", 3600)
      iex> String.contains?(user, ":alice") and byte_size(pass) > 0
      true
  """
  @spec rest_credentials(String.t(), binary(), pos_integer()) :: {String.t(), String.t()}
  def rest_credentials(user_id, secret, ttl_s \\ @default_turn_ttl_s)
      when is_binary(user_id) and is_binary(secret) and ttl_s > 0 do
    expiry = System.system_time(:second) + ttl_s
    username = "#{expiry}:#{user_id}"
    password = :crypto.mac(:hmac, :sha, secret, username) |> Base.encode64()
    {username, password}
  end

  @doc """
  Long-term credential MESSAGE-INTEGRITY key (MD5 of `username:realm:password`).

  ## Examples

      iex> key = XGW.TURN.Client.long_term_key("user", "example.com", "secret")
      iex> key == :crypto.hash(:md5, "user:example.com:secret")
      true
  """
  @spec long_term_key(String.t(), String.t(), String.t()) :: binary()
  def long_term_key(username, realm, password) do
    :crypto.hash(:md5, username <> ":" <> realm <> ":" <> password)
  end

  @doc """
  Unauthenticated TURN Allocate request wire.
  """
  @spec allocate_request(keyword()) :: binary()
  def allocate_request(opts \\ []) do
    attrs =
      %{requested_transport: <<17, 0, 0, 0>>}
      |> maybe_put_username(opts)

    encode_request(:allocate, attrs, opts)
  end

  @doc """
  Performs TURN Allocate with optional 401 challenge handling.

  `cred_opts` keyword: `:turn_username`, `:turn_password`, `:turn_realm`,
  `:turn_secret`, `:turn_user_id`, `:turn_ttl_s`.
  """
  @spec allocate((binary(), {:inet.ip_address(), :inet.port_number()} -> {:ok, binary()} | {:error, term()}), {:inet.ip_address(), :inet.port_number()}, keyword()) ::
          {:ok, allocation()} | {:error, term()}
  def allocate(send_recv, {_, _} = turn_endpoint, cred_opts) when is_function(send_recv, 2) do
    cred_opts = normalize_cred_opts(cred_opts)
    wire = allocate_request(cred_opts)

    with {:ok, resp} <- send_recv.(wire, turn_endpoint),
         {:ok, stun} <- Stun.decode(resp) do
      case stun do
        %Stun{class: :success, method: :allocate} = success ->
          allocation_from_success(success, turn_endpoint, cred_opts)

        %Stun{
          class: :error,
          method: :allocate,
          attrs: %{error_code: {401, _}, nonce: nonce, realm: realm}
        } ->
          do_authed_allocate(send_recv, turn_endpoint, cred_opts, nonce, realm)

        _ ->
          {:error, :allocate_failed}
      end
    end
  end

  @doc """
  Sends TURN Refresh to extend or delete an allocation.
  """
  @spec refresh(
          (binary(), {:inet.ip_address(), :inet.port_number()} -> {:ok, binary()} | {:error, term()}),
          allocation(),
          non_neg_integer()
        ) :: {:ok, allocation()} | {:error, term()}
  def refresh(send_recv, allocation, lifetime_s) when is_function(send_recv, 2) do
    wire = refresh_request(allocation, lifetime_s)

    with {:ok, resp} <- send_recv.(wire, allocation.turn_server),
         {:ok, %Stun{class: :success, method: :refresh} = stun} <-
           decode_response(resp, allocation.integrity_key) do
      lifetime = lifetime_from_attrs(stun.attrs, lifetime_s)
      {:ok, %{allocation | lifetime_s: lifetime}}
    else
      _ -> {:error, :refresh_failed}
    end
  end

  @doc """
  Deletes a TURN allocation (Refresh with lifetime 0).
  """
  @spec delete(
          (binary(), {:inet.ip_address(), :inet.port_number()} -> {:ok, binary()} | {:error, term()}),
          allocation()
        ) :: :ok | {:error, term()}
  def delete(send_recv, allocation) when is_function(send_recv, 2) do
    case refresh(send_recv, allocation, 0) do
      {:ok, _} -> :ok
      {:error, _} = err -> err
    end
  end

  @doc """
  Creates a TURN permission toward `peer_address` (`{ip, port}`).
  """
  @spec create_permission(
          (binary(), {:inet.ip_address(), :inet.port_number()} -> {:ok, binary()} | {:error, term()}),
          allocation(),
          {:inet.ip_address(), :inet.port_number()}
        ) :: :ok | {:error, term()}
  def create_permission(send_recv, allocation, peer_address) when is_function(send_recv, 2) do
    wire = create_permission_request(allocation, peer_address)

    with {:ok, resp} <- send_recv.(wire, allocation.turn_server),
         {:ok, %Stun{class: :success, method: :createperm}} <-
           decode_response(resp, allocation.integrity_key) do
      :ok
    else
      {:ok, %Stun{} = stun} ->
        {:error, {:unexpected_stun, stun.class, stun.method, Map.get(stun.attrs, :error_code)}}

      {:error, reason} ->
        {:error, reason}

      other ->
        {:error, {:create_permission_failed, other}}
    end
  end

  @doc """
  Binds TURN channel `channel` (0x4000..0x7FFF) to `peer_address` on the allocation.
  """
  @spec channel_bind(
          (binary(), {:inet.ip_address(), :inet.port_number()} -> {:ok, binary()} | {:error, term()}),
          allocation(),
          {:inet.ip_address(), :inet.port_number()},
          0x4000..0x7FFF
        ) :: :ok | {:error, term()}
  def channel_bind(send_recv, allocation, peer_address, channel)
      when is_function(send_recv, 2) and channel in 0x4000..0x7FFF do
    wire = channel_bind_request(allocation, peer_address, channel)

    with {:ok, resp} <- send_recv.(wire, allocation.turn_server),
         {:ok, %Stun{class: :success, method: :channelbind}} <-
           decode_response(resp, allocation.integrity_key) do
      :ok
    else
      {:ok, %Stun{} = stun} ->
        {:error, {:unexpected_stun, stun.class, stun.method, Map.get(stun.attrs, :error_code)}}

      {:error, reason} ->
        {:error, reason}

      other ->
        {:error, {:channel_bind_failed, other}}
    end
  end

  @doc """
  Encodes an RFC 5766 ChannelData message (4-byte header + application data + pad).

  ## Examples

      iex> bin = XGW.TURN.Client.encode_channel_data(0x4000, "hi")
      iex> {:ok, 0x4000, "hi"} = XGW.TURN.Client.decode_channel_data(bin)
      iex> true
      true
  """
  @spec encode_channel_data(0x4000..0x7FFF, binary()) :: binary()
  def encode_channel_data(channel, app)
      when channel in 0x4000..0x7FFF and is_binary(app) do
    len = byte_size(app)
    pad = rem(4 - rem(len, 4), 4)
    <<channel::16, len::16, app::binary, 0::size(pad * 8)>>
  end

  @doc """
  Decodes an RFC 5766 ChannelData message.

  Returns `{:ok, channel, app}` or `:error`.

  ## Examples

      iex> XGW.TURN.Client.decode_channel_data(<<0x40, 0x00, 0, 2, "hi", 0, 0>>)
      {:ok, 0x4000, "hi"}

      iex> XGW.TURN.Client.decode_channel_data(<<1, 2, 3>>)
      :error
  """
  @spec decode_channel_data(binary()) :: {:ok, 0x4000..0x7FFF, binary()} | :error
  def decode_channel_data(<<channel::16, len::16, rest::binary>>)
      when channel in 0x4000..0x7FFF and byte_size(rest) >= len do
    <<app::binary-size(^len), _pad::binary>> = rest
    {:ok, channel, app}
  end

  def decode_channel_data(_), do: :error

  @doc """
  Sends a Send Indication with `data` toward `peer_address` through the allocation.
  """
  @spec send_indication(allocation(), {:inet.ip_address(), :inet.port_number()}, binary()) ::
          binary()
  def send_indication(allocation, peer_address, data) do
    attrs = %{
      xor_peer_address: peer_address,
      data: data
    }

    base_attrs =
      if allocation.username != "" do
        Map.merge(attrs, %{
          username: allocation.username,
          realm: allocation.realm,
          nonce: allocation.nonce
        })
      else
        attrs
      end

    encode_request(:send, base_attrs,
      class: :indication,
      integrity: allocation.integrity_key != <<>>,
      key: allocation.integrity_key
    )
  end

  @doc """
  Builds a CreatePermission request for `peer_address` on `allocation`.
  """
  @spec create_permission_request(allocation(), {:inet.ip_address(), :inet.port_number()}) ::
          binary()
  def create_permission_request(allocation, peer_address) do
    attrs = %{
      username: allocation.username,
      realm: allocation.realm,
      nonce: allocation.nonce,
      xor_peer_address: peer_address
    }

    encode_request(:createperm, attrs,
      integrity: allocation.integrity_key != <<>>,
      key: allocation.integrity_key
    )
  end

  @doc """
  Builds a ChannelBind request binding `channel` to `peer_address`.
  """
  @spec channel_bind_request(
          allocation(),
          {:inet.ip_address(), :inet.port_number()},
          0x4000..0x7FFF
        ) :: binary()
  def channel_bind_request(allocation, peer_address, channel)
      when channel in 0x4000..0x7FFF do
    attrs = %{
      username: allocation.username,
      realm: allocation.realm,
      nonce: allocation.nonce,
      xor_peer_address: peer_address,
      channel_number: <<channel::16, 0::16>>
    }

    encode_request(:channelbind, attrs,
      integrity: allocation.integrity_key != <<>>,
      key: allocation.integrity_key
    )
  end

  defp do_authed_allocate(send_recv, turn_endpoint, cred_opts, nonce, realm) do
    {username, password} = credentials(cred_opts)
    key = long_term_key(username, realm, password)

    attrs = %{
      requested_transport: <<17, 0, 0, 0>>,
      username: username,
      realm: realm,
      nonce: nonce
    }

    wire = encode_request(:allocate, attrs, integrity: true, key: key)

    cred_opts =
      cred_opts
      |> Keyword.put(:username, username)
      |> Keyword.put(:realm, realm)
      |> Keyword.put(:nonce, nonce)
      |> Keyword.put(:integrity_key, key)

    with {:ok, resp} <- send_recv.(wire, turn_endpoint),
         {:ok, %Stun{class: :success, method: :allocate} = stun} <- decode_response(resp, key) do
      allocation_from_success(stun, turn_endpoint, cred_opts)
    else
      _ -> {:error, :allocate_failed}
    end
  end

  defp allocation_from_success(
         %Stun{class: :success, method: :allocate, attrs: attrs},
         turn_endpoint,
         cred_opts
       ) do
    with {relay_ip, relay_port} <- Map.get(attrs, :xor_relayed_address),
         true <- is_integer(relay_port) do
      {username, _} = credentials(cred_opts)

      {:ok,
       %{
         turn_server: turn_endpoint,
         relay: {relay_ip, relay_port},
         lifetime_s: lifetime_from_attrs(attrs, 600),
         username: username,
         realm: Keyword.get(cred_opts, :realm, ""),
         nonce: Keyword.get(cred_opts, :nonce, ""),
         integrity_key: Keyword.get(cred_opts, :integrity_key, <<>>)
       }}
    else
      _ -> {:error, :no_relayed_address}
    end
  end

  defp refresh_request(allocation, lifetime_s) do
    attrs = %{
      username: allocation.username,
      realm: allocation.realm,
      nonce: allocation.nonce,
      lifetime: <<lifetime_s::32>>
    }

    encode_request(:refresh, attrs,
      integrity: allocation.integrity_key != <<>>,
      key: allocation.integrity_key
    )
  end

  defp encode_request(method, attrs, opts) do
    integrity? = Keyword.get(opts, :integrity, false)
    key = Keyword.get(opts, :key)
    class = Keyword.get(opts, :class, :request)

    %Stun{
      class: class,
      method: method,
      transactionid: :rand.uniform(0xFFFFFFFFFFFF),
      fingerprint: not integrity?,
      integrity: integrity?,
      key: key,
      attrs: attrs
    }
    |> Stun.encode()
  end

  defp decode_response(resp, key) do
    case Stun.decode(resp, key) do
      {:ok, stun} -> {:ok, stun}
      _ -> Stun.decode(resp)
    end
  end

  defp lifetime_from_attrs(attrs, default) do
    case Map.get(attrs, :lifetime) do
      <<n::32>> when n > 0 -> n
      _ -> default
    end
  end

  defp normalize_cred_opts(cred_opts) when is_list(cred_opts), do: cred_opts
  defp normalize_cred_opts(map) when is_map(map), do: Map.to_list(map)

  defp credentials(cred_opts) do
    cond do
      secret = Keyword.get(cred_opts, :turn_secret) ->
        user_id = Keyword.get(cred_opts, :turn_user_id, "xgw")
        ttl = Keyword.get(cred_opts, :turn_ttl_s, @default_turn_ttl_s)
        rest_credentials(user_id, secret, ttl)

      u = Keyword.get(cred_opts, :turn_username) ->
        {u, Keyword.get(cred_opts, :turn_password, "")}

      u = Keyword.get(cred_opts, :username) ->
        {u, Keyword.get(cred_opts, :password, "")}

      true ->
        {"", ""}
    end
  end

  defp maybe_put_username(attrs, cred_opts) do
    {username, _} = credentials(cred_opts)
    if username != "", do: Map.put(attrs, :username, username), else: attrs
  end

  defp resolve_host(host) do
    char = String.to_charlist(host)

    case :inet.parse_address(char) do
      {:ok, ip} ->
        {:ok, ip}

      {:error, _} ->
        case :inet.getaddr(char, :inet) do
          {:ok, ip} -> {:ok, ip}
          err -> err
        end
    end
  end
end
