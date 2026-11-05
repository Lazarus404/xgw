defmodule XGW.Certs do
  @moduledoc """
  Creates and fingerprints the TLS certificate used for DTLS.

  ## Why certificates matter here

  Before media is encrypted with SRTP, the two peers run a **DTLS** handshake
  (TLS over UDP). Each side presents a certificate. In WebRTC the certificate
  is usually **self-signed**; trust comes from comparing its SHA-256 fingerprint
  to the value advertised in SDP (`a=fingerprint:`), not from a public CA.

  This module:

  - Generates a self-signed cert/key pair with `openssl` when missing (`ensure!/1`).
  - Computes the colon-separated uppercase hex fingerprint browsers expect.
  - Checks that a remote SDP fingerprint matches a DER certificate.

  ## RFCs

  * RFC 8122 -- SDP `a=fingerprint` attribute (certificate digests)
  * RFC 9147 / RFC 6347 -- DTLS (certificate presented during handshake)
  """

  @doc """
  Returns `{certfile, keyfile}` paths, generating a self-signed pair when missing.
  """
  @spec ensure!(Path.t()) :: {Path.t(), Path.t()}
  def ensure!(dir) do
    File.mkdir_p!(dir)

    certfile = Path.join(dir, "xgw.crt")
    keyfile = Path.join(dir, "xgw.key")

    unless File.exists?(certfile) and File.exists?(keyfile) do
      case System.cmd("openssl", [
             "req",
             "-x509",
             "-newkey",
             "rsa:2048",
             "-keyout",
             keyfile,
             "-out",
             certfile,
             "-days",
             "365",
             "-nodes",
             "-subj",
             "/CN=xgw"
           ]) do
        {_, 0} ->
          :ok

        {err, _} ->
          raise "openssl cert generation failed: #{String.trim(err)}"
      end
    end

    {certfile, keyfile}
  end

  @doc """
  SHA-256 fingerprint as colon-separated uppercase hex for SDP.
  """
  @spec fingerprint(Path.t()) :: String.t()
  def fingerprint(certfile) do
    {der, 0} = System.cmd("openssl", ["x509", "-in", certfile, "-outform", "DER"])
    fingerprint_der(der)
  end

  @doc """
  SHA-256 fingerprint as colon-separated uppercase hex from DER bytes.

  ## Examples

      iex> der = :crypto.hash(:sha256, "test")
      iex> fp = XGW.Certs.fingerprint_der(der)
      iex> String.match?(fp, ~r/^[0-9A-F]{2}(:[0-9A-F]{2}){31}$/)
      true
  """
  @spec fingerprint_der(binary()) :: String.t()
  def fingerprint_der(der) when is_binary(der) do
    der
    |> then(&:crypto.hash(:sha256, &1))
    |> Base.encode16(case: :upper)
    |> String.graphemes()
    |> Enum.chunk_every(2)
    |> Enum.map_join(":", &Enum.join/1)
  end

  @doc """
  Returns true when `der` matches an SDP `%Fingerprint{}` (sha-256 only for v1).

  ## Examples

      iex> der = "cert-bytes"
      iex> fp = XGW.Certs.fingerprint_der(der)
      iex> XGW.Certs.fingerprint_matches?(%{algorithm: "sha-256", value: fp}, der)
      true

      iex> XGW.Certs.fingerprint_matches?(%{algorithm: "sha-1", value: "x"}, <<>>)
      false
  """
  @spec fingerprint_matches?(XMediaLib.SDP.Fingerprint.t(), binary()) :: boolean()
  def fingerprint_matches?(%{algorithm: alg, value: value}, der) when is_binary(der) do
    String.downcase(alg) == "sha-256" and
      XGW.Descriptions.normalize_fingerprint(value) == fingerprint_der(der)
  end
end
