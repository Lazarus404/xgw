defmodule XGW.Listener.TCP do
  @moduledoc """
  Accepts ICE-TCP connections and delivers framed STUN to `XGW.Listener`.

  ## ICE-TCP in brief

  Some networks block UDP entirely. WebRTC can then try **TCP candidates**
  (RFC 6544). The Listener optionally opens a passive TCP listen socket; this
  module accepts connections and reads length-prefixed STUN frames
  (`XGW.Stun.TCP`), notifying the Listener with:

  * `{:xgw_internal, :tcp_accept, sock}`
  * framed STUN / closed messages for the established socket

  ## RFCs

  * RFC 6544 -- ICE-TCP (passive TCP candidates)
  * RFC 8489 -- STUN-over-TCP length-prefixed framing
  """

  require Logger

  alias XGW.Stun.TCP, as: StunTCP
  alias XSockets.Transport.TCP, as: XTCP

  @accept_timeout_ms 1_000

  @doc """
  Runs the accept loop (does not return) until the listen socket dies.
  """
  @spec start_acceptor(pid(), :gen_tcp.socket()) :: :no_return
  def start_acceptor(listener, listen_sock) do
    accept_loop(listener, listen_sock)
  end

  @doc """
  Reads one RFC 4571-framed STUN message from `sock`.
  """
  @spec read_stun(:gen_tcp.socket(), timeout()) :: {:ok, binary()} | {:error, term()}
  def read_stun(sock, timeout), do: StunTCP.recv(sock, timeout)

  @doc """
  Sends one RFC 4571-framed STUN message on `sock`.
  """
  @spec send_stun(:gen_tcp.socket(), binary()) :: :ok | {:error, term()}
  def send_stun(sock, wire), do: StunTCP.send(sock, wire)

  @doc """
  Listens for ICE-TCP on `{ip, port}` via xirsys TCP transport.
  """
  @spec listen({:inet.ip_address(), :inet.port_number()}) ::
          {:ok, :gen_tcp.socket()} | {:error, term()}
  def listen({ip, port}) do
    XTCP.listen(ip, port, [])
  end

  defp accept_loop(listener, listen_sock) do
    case XTCP.accept(listen_sock, @accept_timeout_ms) do
      {:ok, client_sock} ->
        send(listener, {:xgw_internal, :tcp_accept, client_sock})
        accept_loop(listener, listen_sock)

      {:error, :timeout} ->
        accept_loop(listener, listen_sock)

      {:error, reason} ->
        Logger.warning("xgw ICE-TCP accept failed: #{inspect(reason)}")
        accept_loop(listener, listen_sock)
    end
  end
end
