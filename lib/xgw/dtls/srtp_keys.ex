defmodule XGW.DTLS.SrtpKeys do
  @moduledoc """
  Turns a finished DTLS handshake into the keys SRTP needs for media.

  ## Plain-language flow

  After DTLS succeeds, TLS has a shared secret but media packets still use a
  different encryption format called **SRTP** (Secure Real-time Transport
  Protocol). RFC 5764 defines how to **export** a fixed-length blob of keying
  material from DTLS and split it into client/server write keys and salts.

  This module:

  1. Calls OTP `:ssl.export_key_materials/4` with the DTLS-SRTP extractor label.
  2. Parses the 60-byte layout into `{client_key, client_salt, server_key, server_salt}`.
  3. Leaves HMAC key derivation to `XMediaLib.Srtp` (SRTP KDF).

  OTP expects the `Contexts` argument as a **list** (for example `[:no_context]`),
  not a bare atom -- a common footgun when calling the exporter by hand.

  ## RFCs

  * RFC 5764 -- DTLS-SRTP key export (`EXTRACTOR-dtls_srtp`) and key/salt layout
  * RFC 3711 -- SRTP (consumes the exported material via SRTP KDF)
  """

  require Logger

  @srtp_export_len 60
  @srtp_key_bytes 16
  @srtp_salt_bytes 14
  @srtp_extractor "EXTRACTOR-dtls_srtp"

  @typedoc "Parsed DTLS-SRTP keying material (client and server write pairs)."
  @type keys :: {client_key :: binary(), client_salt :: binary(), server_key :: binary(),
                 server_salt :: binary()}

  @doc """
  Exports and parses DTLS-SRTP keying material from a connected DTLS socket.
  """
  @spec export(:ssl.sslsocket()) :: {:ok, keys()} | {:error, term()}
  def export(ssl_sock) do
    fetch_and_parse(ssl_sock, @srtp_export_len)
  end

  @doc """
  Parses exported key material (RFC 5764: 60-byte master keys and salts).

  Extra exporter bytes are ignored. HMAC keys are derived by SRTP KDF, not this split.

  ## Examples

      iex> blob = :crypto.strong_rand_bytes(60)
      iex> {:ok, {ck, cs, sk, ss}} = XGW.DTLS.SrtpKeys.parse_materials(blob)
      iex> {byte_size(ck), byte_size(cs), byte_size(sk), byte_size(ss)}
      {16, 14, 16, 14}

      iex> XGW.DTLS.SrtpKeys.parse_materials(<<1, 2, 3>>)
      :error
  """
  @spec parse_materials(binary()) :: {:ok, keys()} | :error
  def parse_materials(materials) when is_binary(materials) do
    case parse_layout(materials) do
      {:ok, keys} -> {:ok, keys}
      :error -> :error
    end
  end

  @doc """
  Like `export/1`, but rescues unexpected errors and returns `{:error, exception}`.
  """
  @spec export_safe(:ssl.sslsocket()) :: {:ok, keys()} | {:error, term()}
  def export_safe(ssl_sock) do
    export(ssl_sock)
  rescue
    e ->
      Logger.warning("xgw DTLS SRTP key export failed: #{inspect(e)}")
      {:error, e}
  end

  defp fetch_and_parse(ssl_sock, len) do
    case fetch_export(ssl_sock, len) do
      {:ok, materials} ->
        case parse_layout(materials) do
          {:ok, keys} -> {:ok, keys}
          :error -> {:error, :bad_layout}
        end

      other ->
        other
    end
  end

  defp fetch_export(ssl_sock, len) do
    case :ssl.export_key_materials(ssl_sock, [@srtp_extractor], [:no_context], [len])
         |> normalize_export() do
      {:ok, _} = ok ->
        ok

      _ ->
        :ssl.export_key_materials(ssl_sock, [@srtp_extractor], [<<>>], [len])
        |> normalize_export()
    end
  end

  defp normalize_export({:ok, materials}) when is_binary(materials), do: {:ok, materials}
  defp normalize_export({:ok, [materials]}) when is_binary(materials), do: {:ok, materials}
  defp normalize_export(other), do: other

  defp parse_layout(materials) when byte_size(materials) >= @srtp_export_len do
    <<client_key::binary-size(@srtp_key_bytes), server_key::binary-size(@srtp_key_bytes),
      client_salt::binary-size(@srtp_salt_bytes), server_salt::binary-size(@srtp_salt_bytes),
      _::binary>> = materials

    {:ok, {client_key, client_salt, server_key, server_salt}}
  end

  defp parse_layout(_), do: :error
end
