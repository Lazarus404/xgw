defmodule XGW.Demux do
  @moduledoc """
  Separates mixed UDP packets that share one socket into STUN, DTLS, and media.

  ## Why demux exists

  WebRTC reuses a single 5-tuple (same IP/port pair) for several protocols at
  once: connectivity probes (**STUN**), the security handshake (**DTLS**), and
  the media itself (**RTP** / **RTCP**). The first byte of each datagram tells
  you which protocol it is (RFC 7983). This module only classifies bytes; it
  does not parse STUN attributes or decrypt SRTP.

  RTP and RTCP can also share the same port (**RTCP-mux**, RFC 5761). When the
  first-byte range is the media bucket (128-191), `classify_media/1` looks at
  the RTP payload type field: values 64-95 mean RTCP, otherwise RTP.

  ## RFCs

  * RFC 7983 -- first-byte demultiplexing of STUN, DTLS, ZRTP, TURN ChannelData, RTP/RTCP
  * RFC 5761 -- RTP/RTCP multiplexing (payload-type split in the media range)
  """

  @typedoc "RFC 7983 first-byte protocol bucket."
  @type protocol :: :stun | :zrtp | :dtls | :turn_channel | :rtp_rtcp | :unknown

  @typedoc "Full ingress classification including RTP vs RTCP split."
  @type kind :: :stun | :zrtp | :dtls | :turn_channel | :rtp | :rtcp | :unknown

  @doc """
  Classifies a packet by its first byte (RFC 7983).

  ## Examples

      iex> XGW.Demux.classify(<<0, 0, 0, 0>>)
      {:ok, :stun}

      iex> XGW.Demux.classify(<<22, 0>>)
      {:ok, :dtls}

      iex> XGW.Demux.classify(<<128, 0>>)
      {:ok, :rtp_rtcp}

      iex> XGW.Demux.classify(<<>>)
      {:error, :empty}
  """
  @spec classify(binary()) :: {:ok, protocol()} | {:error, :empty}
  def classify(<<>>), do: {:error, :empty}

  def classify(<<b, _::binary>>) when b in 0..3, do: {:ok, :stun}
  def classify(<<b, _::binary>>) when b in 16..19, do: {:ok, :zrtp}
  def classify(<<b, _::binary>>) when b in 20..63, do: {:ok, :dtls}
  def classify(<<b, _::binary>>) when b in 64..79, do: {:ok, :turn_channel}
  def classify(<<b, _::binary>>) when b in 128..191, do: {:ok, :rtp_rtcp}
  def classify(_), do: {:ok, :unknown}

  @doc """
  Classifies an RFC 7983 RTP/RTCP-range packet as RTP or RTCP (RFC 5761 mux PT rule).

  ## Examples

      iex> XGW.Demux.classify_media(<<2::2, 0::6, 0::1, 63::7, 0::16, 0::32, 0::32>>)
      {:ok, :rtp}

      iex> XGW.Demux.classify_media(<<2::2, 0::6, 0::1, 64::7, 0::16, 0::32, 0::32>>)
      {:ok, :rtcp}

      iex> XGW.Demux.classify_media(<<128>>)
      {:error, :too_short}
  """
  @spec classify_media(binary()) :: {:ok, :rtp | :rtcp} | {:error, :too_short}
  def classify_media(<<2::2, _::6, _m::1, pt::7, _::binary>>) when pt in 64..95,
    do: {:ok, :rtcp}

  def classify_media(<<2::2, _::6, _m::1, _pt::7, _::binary>>), do: {:ok, :rtp}
  def classify_media(_), do: {:error, :too_short}

  @doc """
  Full ingress classification: RFC 7983 first byte, then media PT split when applicable.

  ## Examples

      iex> XGW.Demux.classify_kind(<<0, 1, 2>>)
      {:ok, :stun}

      iex> XGW.Demux.classify_kind(<<22, 0>>)
      {:ok, :dtls}

      iex> XGW.Demux.classify_kind(<<128, 111, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0>>)
      {:ok, :rtp}
  """
  @spec classify_kind(binary()) :: {:ok, kind()} | {:error, :empty | :too_short}
  def classify_kind(<<>>), do: {:error, :empty}

  def classify_kind(data) do
    case classify(data) do
      {:ok, :rtp_rtcp} -> classify_media(data)
      {:ok, kind} -> {:ok, kind}
      {:error, _} = error -> error
    end
  end
end
