defmodule XGW.DTLS do
  @moduledoc """
  Starts and completes the DTLS handshake that unlocks encrypted media keys.

  ## Why DTLS comes after ICE

  **ICE** only finds a working IP/port path. That path is still unauthenticated
  for media encryption. **DTLS** (Datagram TLS) is TLS over UDP: the two peers
  exchange certificates, prove possession of private keys, and agree on
  cryptographic material. WebRTC then derives **SRTP** keys from that material
  so RTP/RTCP packets can be encrypted efficiently.

  This module is the server-side accept path used by `XGW.Peer`:

  - listen/accept on the shared Listener UDP socket via `XGW.DTLS.Transport`
  - finish the handshake and verify the remote fingerprint
  - export SRTP keys through `XGW.DTLS.SrtpKeys`

  Start the accept loop only after ICE has selected a remote pair; otherwise
  DTLS packets have nowhere trustworthy to go.

  ## RFCs

  * RFC 9147 / RFC 6347 -- DTLS 1.3 / 1.2
  * RFC 5764 -- DTLS extension for SRTP key export
  * RFC 8122 -- certificate fingerprint verification against SDP
  """

  require Logger

  alias XGW.{Certs, DTLS.SrtpKeys, DTLS.Transport}
  alias XMediaLib.SDP.Fingerprint

  @dtls_timeout 120_000

  @typedoc "DTLS-exported SRTP key tuple (client and server write pairs)."
  @type keys :: SrtpKeys.keys()

  @doc """
  Starts a linked accept loop on `listen_sock`. Completion is reported to
  `peer` as `{:xgw_internal, :dtls_ready, ssl_sock, export_result}`.

  Options:

    * `:expected_fingerprint` - remote `%Fingerprint{}` from SDP offer
  """
  @spec start_accept(:ssl.sslsocket(), pid(), keyword()) :: {:ok, pid()}
  def start_accept(listen_sock, peer, opts \\ []) when is_pid(peer) do
    expected = Keyword.get(opts, :expected_fingerprint)
    Task.start(fn -> accept_loop(listen_sock, peer, expected) end)
  end

  @doc """
  Injects a DTLS datagram into the OTP ssl transport on the listener UDP socket.
  """
  @spec inject(pid(), :inet.ip_address(), :inet.port_number(), binary()) :: :ok
  def inject(listener, ip, port, data) do
    GenServer.cast(listener, {:inject_dtls, ip, port, data})
  end

  @doc """
  Completes transport accept and DTLS handshake on `listen_sock`.
  """
  @spec handshake(:ssl.sslsocket()) :: {:ok, :ssl.sslsocket()} | {:error, term()}
  def handshake(listen_sock) do
    with {:ok, dtls_sock} <- :ssl.transport_accept(listen_sock, @dtls_timeout),
         {:ok, ssl_sock} <- :ssl.handshake(dtls_sock, @dtls_timeout) do
      {:ok, ssl_sock}
    end
  end

  @doc """
  Exports DTLS-SRTP keying material from a connected DTLS socket.
  """
  @spec export_srtp_keys(:ssl.sslsocket()) :: {:ok, keys()} | {:error, term()}
  def export_srtp_keys(ssl_sock), do: SrtpKeys.export(ssl_sock)

  @doc """
  Verifies the peer certificate fingerprint against SDP.
  """
  @spec verify_fingerprint(:ssl.sslsocket(), Fingerprint.t()) :: boolean()
  def verify_fingerprint(ssl_sock, %Fingerprint{} = expected) do
    case :ssl.peercert(ssl_sock) do
      {:ok, der} when is_binary(der) -> Certs.fingerprint_matches?(expected, der)
      der when is_binary(der) -> Certs.fingerprint_matches?(expected, der)
      _ -> false
    end
  end

  @doc """
  Closes DTLS listen and connection sockets.
  """
  @spec close(:ssl.sslsocket() | nil, :ssl.sslsocket() | nil) :: :ok
  def close(listen_sock, ssl_sock \\ nil) do
    if ssl_sock, do: :ssl.close(ssl_sock)
    if listen_sock, do: :ssl.close(listen_sock)
    :ok
  end

  @doc """
  SSL listen options for WebRTC DTLS-SRTP on a shared UDP port.
  """
  @spec listen_opts(keyword()) :: keyword()
  def listen_opts(opts) when is_list(opts) do
    certfile = Keyword.fetch!(opts, :certfile)
    keyfile = Keyword.fetch!(opts, :keyfile)
    port = Keyword.fetch!(opts, :port)

    accept_any =
      {fn _cert, _event, state -> {:valid, state} end, nil}

    [
      active: false,
      # OTP DTLS defaults to mode:list; Peer SCTP path requires binaries.
      mode: :binary,
      verify: :verify_peer,
      cacerts: [],
      verify_fun: accept_any,
      fail_if_no_peer_cert: true,
      certfile: String.to_charlist(certfile),
      keyfile: String.to_charlist(keyfile),
      protocol: :dtls,
      versions: [:"dtlsv1.2"],
      reuseaddr: true,
      use_srtp: %{protection_profiles: [<<0, 1>>]},
      cb_info: {Transport, :udp, :udp_closed, :udp_error},
      port: port
    ]
  end

  defp take_over(ssl_sock, peer) do
    # Peer must receive {:ssl, ...} but must not become the UDP cb owner.
    _ = Transport.ignore_owner(peer)

    case :ssl.controlling_process(ssl_sock, peer) do
      :ok ->
        :ok

      {:error, reason} ->
        Logger.warning("xgw DTLS controlling_process failed: #{inspect(reason)}")
        {:error, reason}
    end
  end

  defp accept_loop(listen_sock, peer, expected_fp) do
    case :ssl.transport_accept(listen_sock, @dtls_timeout) do
      {:ok, dtls_sock} ->
        finish_handshake(listen_sock, dtls_sock, peer, expected_fp)

      {:error, :timeout} ->
        accept_loop(listen_sock, peer, expected_fp)

      {:error, reason} ->
        Logger.warning("xgw DTLS accept failed: #{inspect(reason)}")
        send(peer, {:xgw_internal, :dtls_error, reason})
        :ok
    end
  end

  defp finish_handshake(listen_sock, dtls_sock, peer, expected_fp) do
    case :ssl.handshake(dtls_sock, @dtls_timeout) do
      {:ok, ssl_sock} ->
        # Export before peercert/fingerprint. On current OTP DTLS + cb_info,
        # :ssl.peercert/1 before export_key_materials leaves the sock unusable
        # for SRTP export ({:error, :closed}).
        export = SrtpKeys.export_safe(ssl_sock)

        if expected_fp && !verify_fingerprint(ssl_sock, expected_fp) do
          Logger.warning("xgw DTLS fingerprint mismatch")
          :ssl.close(ssl_sock)
          send(peer, {:xgw_internal, :dtls_fingerprint_mismatch})
          accept_loop(listen_sock, peer, expected_fp)
        else
          take_over(ssl_sock, peer)
          send(peer, {:xgw_internal, :dtls_ready, ssl_sock, export})
        end

      {:error, reason} ->
        Logger.warning("xgw DTLS handshake failed: #{inspect(reason)}")
        send(peer, {:xgw_internal, :dtls_error, reason})
        :ssl.close(dtls_sock)
        accept_loop(listen_sock, peer, expected_fp)
    end
  rescue
    e ->
      Logger.warning("xgw DTLS handshake crashed: #{inspect(e)}")
      send(peer, {:xgw_internal, :dtls_error, e})
      accept_loop(listen_sock, peer, expected_fp)
  end
end
