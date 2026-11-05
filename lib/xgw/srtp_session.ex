defmodule XGW.SRTPSession do
  @moduledoc """
  Encrypts and decrypts media packets for one Peer after DTLS succeeds.

  ## SRTP vs DTLS

  **DTLS** is used once (handshake) to agree on keys. Ongoing audio/video uses
  **SRTP** / **SRTCP**: a compact encryption format wrapped around RTP/RTCP so
  every media packet does not pay full TLS record overhead.

  XGW is the DTLS **server**, so:

  * **client** write keys decrypt inbound packets from the browser
  * **server** write keys encrypt outbound packets to the browser

  Separate `XMediaLib.Srtp` contexts are kept per `{kind, ssrc}` for `:rtp`
  and `:rtcp` so each stream can advance its own replay/ROC state.

  ## RFCs

  * RFC 3711 -- SRTP / SRTCP encrypt and decrypt
  * RFC 5764 -- DTLS-exported client/server write keys and salts
  """

  require Logger

  alias XMediaLib.{Rtcp, Rtp, Srtp}

  @typedoc """
  DTLS-exported SRTP keying material (RFC 5764 client/server write pairs).

  Ordered as `{client_key, client_salt, server_key, server_salt}`.
  """
  @type keys :: {client_key :: binary(), client_salt :: binary(), server_key :: binary(),
                 server_salt :: binary()}

  @typedoc """
  Per-peer SRTP session state.
  """
  @type t :: %__MODULE__{
          client_key: binary() | nil,
          client_salt: binary() | nil,
          server_key: binary() | nil,
          server_salt: binary() | nil,
          decrypt_contexts: %{optional({:rtp | :rtcp, non_neg_integer()}) => term()},
          encrypt_contexts: %{optional({:rtp | :rtcp, non_neg_integer()}) => term()},
          fail_logged: MapSet.t()
        }

  @doc """
  Per-peer SRTP encrypt/decrypt state.

  ## Fields

  * `:client_key` / `:client_salt` - client write keys (inbound decrypt)
  * `:server_key` / `:server_salt` - server write keys (outbound encrypt)
  * `:decrypt_contexts` - per `{kind, ssrc}` `XMediaLib.Srtp` decrypt contexts
  * `:encrypt_contexts` - per `{kind, ssrc}` `XMediaLib.Srtp` encrypt contexts
  * `:fail_logged` - kinds that already logged a decrypt/encrypt failure
  """
  defstruct client_key: nil,
            client_salt: nil,
            server_key: nil,
            server_salt: nil,
            decrypt_contexts: %{},
            encrypt_contexts: %{},
            fail_logged: MapSet.new()

  @doc """
  Builds a session from DTLS-exported SRTP keying material.
  """
  @spec new(keys()) :: t()
  def new({client_key, client_salt, server_key, server_salt}) do
    %__MODULE__{
      client_key: client_key,
      client_salt: client_salt,
      server_key: server_key,
      server_salt: server_salt,
      decrypt_contexts: %{},
      encrypt_contexts: %{}
    }
  end

  @doc """
  Encrypt-only view for the hot-path send handle (no inbound decrypt state).
  """
  @spec outbound(t()) :: t()
  def outbound(%__MODULE__{} = session) do
    %{
      session
      | client_key: nil,
        client_salt: nil,
        decrypt_contexts: %{}
    }
  end

  @doc """
  Decrypts one RTP or RTCP SRTP packet.

  Returns `{:ok, plaintext, session}` on success. Failures are dropped after one
  warning log per kind (`:rtp` / `:rtcp`).
  """
  @spec decrypt(t(), :rtp | :rtcp, binary()) :: {:ok, term(), t()} | {:error, t()}
  def decrypt(%__MODULE__{client_key: key, client_salt: salt} = session, kind, ciphertext)
      when kind in [:rtp, :rtcp] and is_binary(key) and is_binary(salt) and is_binary(ciphertext) do
    with ssrc when is_integer(ssrc) <- ssrc_for(kind, ciphertext),
         ctx <- decrypt_context_for(session, kind, ssrc, key, salt),
         {:ok, plaintext, ctx2} <- Srtp.decrypt(ciphertext, ctx) do
      # Keep fail_logged on success so a later stray packet does not re-warn once per flap.
      {:ok, plaintext,
       %{session | decrypt_contexts: Map.put(session.decrypt_contexts, ctx_key(kind, ssrc), ctx2)}}
    else
      _ ->
        {:error, log_fail_once(session, :decrypt, kind, ciphertext)}
    end
  rescue
    _ -> {:error, log_fail_once(session, :decrypt, kind, ciphertext)}
  end

  def decrypt(session, _kind, _ciphertext), do: {:error, session}

  @doc """
  Encrypts one plaintext RTP or RTCP packet with server write keys.

  Returns `{:ok, ciphertext, session}` on success.
  """
  @spec encrypt(t(), :rtp, Rtp.t()) :: {:ok, binary(), t()} | {:error, t()}
  @spec encrypt(t(), :rtcp, Rtcp.t()) :: {:ok, binary(), t()} | {:error, t()}
  def encrypt(%__MODULE__{server_key: key, server_salt: salt} = session, :rtp, %Rtp{ssrc: ssrc} = rtp)
      when is_binary(key) and is_binary(salt) and is_integer(ssrc) do
    ctx = encrypt_context_for(session, :rtp, ssrc, key, salt)

    case Srtp.encrypt(rtp, ctx) do
      {:ok, ciphertext, ctx2} ->
        {:ok, ciphertext,
         %{
           session
           | encrypt_contexts: Map.put(session.encrypt_contexts, ctx_key(:rtp, ssrc), ctx2),
             fail_logged: MapSet.delete(session.fail_logged, :rtp)
         }}
    end
  rescue
    _ -> {:error, log_fail_once(session, :encrypt, :rtp, rtp)}
  end

  def encrypt(%__MODULE__{server_key: key, server_salt: salt} = session, :rtcp, %Rtcp{} = rtcp)
      when is_binary(key) and is_binary(salt) do
    with ssrc when is_integer(ssrc) <- rtcp_plaintext_ssrc(rtcp),
         ctx <- encrypt_context_for(session, :rtcp, ssrc, key, salt),
         {:ok, ciphertext, ctx2} <- Srtp.encrypt(rtcp, ctx) do
      {:ok, ciphertext,
       %{
         session
         | encrypt_contexts: Map.put(session.encrypt_contexts, ctx_key(:rtcp, ssrc), ctx2),
           fail_logged: MapSet.delete(session.fail_logged, :rtcp)
         }}
    else
      _ ->
        {:error, log_fail_once(session, :encrypt, :rtcp, rtcp)}
    end
  rescue
    _ -> {:error, log_fail_once(session, :encrypt, :rtcp, rtcp)}
  end

  def encrypt(session, _kind, _plaintext), do: {:error, session}

  defp ctx_key(kind, ssrc) when kind in [:rtp, :rtcp] and is_integer(ssrc), do: {kind, ssrc}

  defp decrypt_context_for(%{decrypt_contexts: contexts}, kind, ssrc, key, salt) do
    Map.get_lazy(contexts, ctx_key(kind, ssrc), fn ->
      Srtp.new_ctx(ssrc, :aes_cm, :hmac_sha1, key, salt, 10)
    end)
  end

  defp encrypt_context_for(%{encrypt_contexts: contexts}, kind, ssrc, key, salt) do
    Map.get_lazy(contexts, ctx_key(kind, ssrc), fn ->
      Srtp.new_ctx(ssrc, :aes_cm, :hmac_sha1, key, salt, 10)
    end)
  end

  defp ssrc_for(:rtp, ciphertext), do: rtp_ssrc(ciphertext)
  defp ssrc_for(:rtcp, ciphertext), do: rtcp_ssrc(ciphertext)

  defp rtp_ssrc(ciphertext) do
    <<2::2, _::6, _m::1, _pt::7, _seq::16, _ts::32, ssrc::32, _::binary>> = ciphertext
    ssrc
  rescue
    _ -> nil
  end

  defp rtcp_ssrc(ciphertext) do
    <<2::2, _::6, _pt::8, _len::16, ssrc::32, _::binary>> = ciphertext
    ssrc
  rescue
    _ -> nil
  end

  defp rtcp_plaintext_ssrc(%Rtcp{payloads: [first | _]}) do
    Map.get(first, :ssrc) || Map.get(first, :ssrc_s)
  end

  defp rtcp_plaintext_ssrc(_), do: nil

  defp log_fail_once(session, op, kind, data) do
    if MapSet.member?(session.fail_logged, kind) do
      session
    else
      log_fail(op, kind, data)
      %{session | fail_logged: MapSet.put(session.fail_logged, kind)}
    end
  end

  defp log_fail(op, kind, ciphertext) when is_binary(ciphertext) and kind in [:rtp, :rtcp] do
    {pt, seq, ssrc} = header_fields(ciphertext, kind)

    Logger.warning(
      "xgw SRTP #{op} failed kind=#{kind} pt=#{pt} seq=#{seq} ssrc=#{ssrc} len=#{byte_size(ciphertext)}"
    )
  end

  defp log_fail(op, kind, _data) do
    Logger.warning("xgw SRTP #{op} failed kind=#{kind}")
  end

  defp header_fields(ciphertext, :rtp) do
    <<2::2, _::6, _m::1, pt::7, seq::16, _::32, ssrc::32, _::binary>> = ciphertext
    {pt, seq, ssrc}
  rescue
    _ -> {"?", "?", "?"}
  end

  defp header_fields(ciphertext, :rtcp) do
    <<2::2, _::6, pt::8, _len::16, ssrc::32, _::binary>> = ciphertext
    {pt, "?", ssrc}
  rescue
    _ -> {"?", "?", "?"}
  end
end
