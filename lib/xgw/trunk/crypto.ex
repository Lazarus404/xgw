defmodule XGW.Trunk.Crypto do
  @moduledoc """
  Static-key SRTP for inter-edge trunk pipes.

  ## What problem this solves

  Trunk edges exchange write-key pairs over the control plane, then protect
  RTP/RTCP on the UDP pipe without DTLS. Each edge encrypts with its local
  write key and decrypts with the far edge's write key.

  ## RFCs

  * RFC 3711 -- SRTP encrypt / decrypt
  """

  alias XGW.SRTPSession
  alias XMediaLib.{Rtcp, Rtp}

  @doc """
  Lab alias: shared master material for both directions (`local == remote`).
  """
  @spec new(binary(), binary()) :: SRTPSession.t()
  def new(master_key, master_salt)
      when is_binary(master_key) and is_binary(master_salt) and
             byte_size(master_key) == 16 and byte_size(master_salt) == 14 do
    new(master_key, master_salt, master_key, master_salt)
  end

  @doc """
  Builds an `XGW.SRTPSession` from directional write keys.

  Encrypt uses `local_write_*` (SRTP server write). Decrypt uses
  `remote_write_*` (SRTP client write). The far edge passes the swapped pair.
  """
  @spec new(binary(), binary(), binary(), binary()) :: SRTPSession.t()
  def new(local_write_key, local_write_salt, remote_write_key, remote_write_salt)
      when is_binary(local_write_key) and is_binary(local_write_salt) and
             is_binary(remote_write_key) and is_binary(remote_write_salt) and
             byte_size(local_write_key) == 16 and byte_size(local_write_salt) == 14 and
             byte_size(remote_write_key) == 16 and byte_size(remote_write_salt) == 14 do
    SRTPSession.new(
      {remote_write_key, remote_write_salt, local_write_key, local_write_salt}
    )
  end

  @doc """
  Encrypts RTP; returns ciphertext and updated session.
  """
  @spec protect_rtp(SRTPSession.t(), Rtp.t()) ::
          {:ok, binary(), SRTPSession.t()} | {:error, SRTPSession.t()}
  def protect_rtp(%SRTPSession{} = session, %Rtp{} = rtp) do
    SRTPSession.encrypt(session, :rtp, rtp)
  end

  @doc """
  Decrypts SRTP to `%Rtp{}`.
  """
  @spec unprotect_rtp(SRTPSession.t(), binary()) ::
          {:ok, Rtp.t(), SRTPSession.t()} | {:error, SRTPSession.t()}
  def unprotect_rtp(%SRTPSession{} = session, ciphertext) when is_binary(ciphertext) do
    SRTPSession.decrypt(session, :rtp, ciphertext)
  end

  @doc """
  Encrypts RTCP.
  """
  @spec protect_rtcp(SRTPSession.t(), Rtcp.t()) ::
          {:ok, binary(), SRTPSession.t()} | {:error, SRTPSession.t()}
  def protect_rtcp(%SRTPSession{} = session, %Rtcp{} = rtcp) do
    SRTPSession.encrypt(session, :rtcp, rtcp)
  end

  @doc """
  Decrypts SRTCP.
  """
  @spec unprotect_rtcp(SRTPSession.t(), binary()) ::
          {:ok, term(), SRTPSession.t()} | {:error, SRTPSession.t()}
  def unprotect_rtcp(%SRTPSession{} = session, ciphertext) when is_binary(ciphertext) do
    SRTPSession.decrypt(session, :rtcp, ciphertext)
  end
end
