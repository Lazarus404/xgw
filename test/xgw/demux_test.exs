defmodule XGW.DemuxTest do
  use ExUnit.Case, async: true
  doctest XGW.Demux

  alias XGW.Demux

  test "classifies RFC 7983 first-byte ranges" do
    assert {:ok, :stun} = Demux.classify(<<0, 0, 0, 0>>)
    assert {:ok, :dtls} = Demux.classify(<<22, 0>>)
    assert {:ok, :rtp_rtcp} = Demux.classify(<<128, 0>>)
    assert {:ok, :unknown} = Demux.classify(<<255, 0>>)
    assert {:error, :empty} = Demux.classify(<<>>)
  end

  test "classify_media splits RTP vs RTCP by 7-bit PT (RFC 5761 mux)" do
    # V=2, M=0, PT=63 -> RTP
    assert {:ok, :rtp} = Demux.classify_media(<<2::2, 0::6, 0::1, 63::7, 0::16, 0::32, 0::32>>)
    # V=2, M=0, PT=64 -> RTCP
    assert {:ok, :rtcp} = Demux.classify_media(<<2::2, 0::6, 0::1, 64::7, 0::16, 0::32, 0::32>>)
    # V=2, M=0, PT=95 -> RTCP
    assert {:ok, :rtcp} = Demux.classify_media(<<2::2, 0::6, 0::1, 95::7, 0::16, 0::32, 0::32>>)
    # V=2, M=0, PT=96 -> RTP
    assert {:ok, :rtp} = Demux.classify_media(<<2::2, 0::6, 0::1, 96::7, 0::16, 0::32, 0::32>>)
    assert {:error, :too_short} = Demux.classify_media(<<128>>)
  end

  test "classify_media treats SRTP clear-header RTCP PT 200 as RTCP" do
    # Byte2 = 200 (M=1, PT=72); PT 72 is in 64..95
    assert {:ok, :rtcp} =
             Demux.classify_media(<<128, 200, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0>>)
  end

  test "classify_kind refines rtp_rtcp range" do
    assert {:ok, :stun} = Demux.classify_kind(<<0, 1, 2>>)
    assert {:ok, :dtls} = Demux.classify_kind(<<22, 0>>)
    assert {:ok, :rtp} = Demux.classify_kind(<<128, 111, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0>>)
    assert {:ok, :rtcp} = Demux.classify_kind(<<128, 200, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0>>)
  end
end
