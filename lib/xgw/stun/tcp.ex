defmodule XGW.Stun.TCP do
  @moduledoc """
  Frames STUN messages for transport over TCP (RFC 8489).

  ## Why TCP framing exists

  On UDP, each datagram is already one STUN message. On TCP, bytes stream
  without message boundaries, so each STUN PDU is prefixed with a 16-bit
  big-endian length. ICE-TCP (RFC 6544) uses this framing when UDP is blocked
  and peers fall back to TCP candidates.

  Helpers: `frame/1` for encode, `recv/2` / `send/2` for socket I/O.

  ## RFCs

  * RFC 8489 -- STUN-over-TCP framing (16-bit length prefix)
  * RFC 6544 -- ICE-TCP usage of that framing
  """

  @doc """
  Prefixes a STUN wire with its 16-bit big-endian length.

  ## Examples

      iex> XGW.Stun.TCP.frame(<<1, 2, 3>>)
      <<0, 3, 1, 2, 3>>
  """
  @spec frame(binary()) :: binary()
  def frame(wire) when is_binary(wire) do
    <<byte_size(wire)::16, wire::binary>>
  end

  @doc """
  Reads one framed STUN message from `sock`. Returns `{:ok, wire}` or `{:error, reason}`.
  """
  @spec recv(:gen_tcp.socket(), timeout()) :: {:ok, binary()} | {:error, term()}
  def recv(sock, timeout) do
    with {:ok, <<len::16, rest::binary>>} <- :gen_tcp.recv(sock, 2, timeout),
         need when need >= 0 <- len - byte_size(rest),
         {:ok, wire} <- recv_exact(sock, rest, need, timeout) do
      {:ok, wire}
    else
      {:error, _} = err -> err
      :error -> {:error, :tcp_closed}
    end
  end

  @doc """
  Sends one framed STUN message on `sock`.
  """
  @spec send(:gen_tcp.socket(), binary()) :: :ok | {:error, term()}
  def send(sock, wire) when is_binary(wire) do
    :gen_tcp.send(sock, frame(wire))
  end

  defp recv_exact(_sock, acc, 0, _timeout), do: {:ok, acc}

  defp recv_exact(sock, acc, need, timeout) do
    case :gen_tcp.recv(sock, need, timeout) do
      {:ok, chunk} -> recv_exact(sock, acc <> chunk, need - byte_size(chunk), timeout)
      other -> other
    end
  end
end
