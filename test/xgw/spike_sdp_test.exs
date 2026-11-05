defmodule XGW.Spike.SDPTest do
  use ExUnit.Case, async: true

  alias XGW.Spike.SDP
  alias XGW.Test.SDPFixtures

  test "answer prefers non-loopback default address when available" do
    answer =
      SDP.answer(SDPFixtures.chrome_offer(),
        ice_ufrag: "svr1",
        ice_pwd: "serverpasswordpassword",
        fingerprint: SDPFixtures.chrome_fingerprint(),
        port: 10_000,
        ip: {127, 0, 0, 1},
        ips: [{127, 0, 0, 1}, {192, 168, 0, 5}]
      )

    assert answer =~ "o=- 0 0 IN IP4 192.168.0.5\r\n"
    assert answer =~ "c=IN IP4 192.168.0.5\r\n"
    assert answer =~ "a=candidate:1 1 udp 2130706431 127.0.0.1 10000 typ host\r\n"
    assert answer =~ "a=candidate:2 1 udp 2130706431 192.168.0.5 10000 typ host\r\n"
  end

  test "relay candidate lines set m= and c= to the relayed address" do
    answer =
      SDP.answer(SDPFixtures.chrome_offer(),
        ice_ufrag: "svr1",
        ice_pwd: "serverpasswordpassword",
        fingerprint: SDPFixtures.chrome_fingerprint(),
        port: 10_000,
        ip: {127, 0, 0, 1},
        ips: [{192, 168, 0, 5}],
        candidate_lines: [
          "candidate:9 1 UDP 16777215 203.0.113.99 49999 typ relay"
        ]
      )

    assert answer =~ "m=audio 49999 UDP/TLS/RTP/SAVPF"
    assert answer =~ "c=IN IP4 203.0.113.99\r\n"
    assert answer =~ "a=candidate:9 1 UDP 16777215 203.0.113.99 49999 typ relay\r\n"
    refute answer =~ "m=audio 10000 "
  end

  test "answer echoes audio extmaps, rtcp-rsize, and ice-options:trickle from offer" do
    offer = """
    v=0
    o=- 1 2 IN IP4 127.0.0.1
    s=-
    t=0 0
    a=group:BUNDLE 0 1
    a=ice-options:trickle
    m=audio 9 UDP/TLS/RTP/SAVPF 111
    c=IN IP4 0.0.0.0
    a=ice-ufrag:cli1
    a=ice-pwd:clientpasswordpassword
    a=fingerprint:sha-256 #{SDPFixtures.chrome_fingerprint()}
    a=setup:actpass
    a=mid:0
    a=extmap:1 urn:ietf:params:rtp-hdrext:ssrc-audio-level
    a=extmap:2 http://www.webrtc.org/experiments/rtp-hdrext/abs-send-time
    a=sendrecv
    a=rtcp-mux
    a=rtcp-rsize
    a=rtpmap:111 opus/48000/2
    m=video 9 UDP/TLS/RTP/SAVPF 96
    a=mid:1
    a=extmap:3 urn:ietf:params:rtp-hdrext:sdes:mid
    a=rtpmap:96 VP8/90000
    """

    answer =
      SDP.answer(offer,
        ice_ufrag: "svr1",
        ice_pwd: "serverpasswordpassword",
        fingerprint: SDPFixtures.chrome_fingerprint(),
        port: 10_000,
        ip: {192, 168, 0, 5}
      )

    assert answer =~ "a=ice-options:trickle\r\n"
    assert answer =~ "a=rtcp-rsize\r\n"
    assert answer =~ "a=extmap:1 urn:ietf:params:rtp-hdrext:ssrc-audio-level\r\n"
    assert answer =~ "a=extmap:2 http://www.webrtc.org/experiments/rtp-hdrext/abs-send-time\r\n"
    refute answer =~ "a=extmap:3"
    refute answer =~ "m=video"
  end

  test "answer forces PCMU only when codec: :pcmu" do
    offer = """
    v=0
    o=- 1 2 IN IP4 127.0.0.1
    s=-
    t=0 0
    a=group:BUNDLE 0
    m=audio 9 UDP/TLS/RTP/SAVPF 111 0 8 9
    c=IN IP4 0.0.0.0
    a=ice-ufrag:cli1
    a=ice-pwd:clientpasswordpassword
    a=fingerprint:sha-256 #{SDPFixtures.chrome_fingerprint()}
    a=setup:actpass
    a=mid:0
    a=sendrecv
    a=rtcp-mux
    a=rtpmap:111 opus/48000/2
    a=fmtp:111 minptime=10;useinbandfec=1
    a=rtpmap:0 PCMU/8000
    a=rtpmap:8 PCMA/8000
    a=rtpmap:9 G722/8000
    """

    answer =
      SDP.answer(offer,
        ice_ufrag: "svr1",
        ice_pwd: "serverpasswordpassword",
        fingerprint: SDPFixtures.chrome_fingerprint(),
        port: 10_000,
        ip: {192, 168, 0, 5},
        codec: :pcmu
      )

    assert answer =~ "m=audio 10000 UDP/TLS/RTP/SAVPF 0\r\n"
    assert answer =~ "a=rtpmap:0 PCMU/8000\r\n"
    refute answer =~ "opus"
    refute answer =~ "PCMA"
    refute answer =~ "G722"
  end

  test "answer includes SCTP application m-line when offer has datachannel" do
    offer = """
    v=0
    o=- 1 2 IN IP4 127.0.0.1
    s=-
    t=0 0
    a=group:BUNDLE 0 1
    m=audio 9 UDP/TLS/RTP/SAVPF 111
    c=IN IP4 0.0.0.0
    a=ice-ufrag:cli1
    a=ice-pwd:clientpasswordpassword
    a=fingerprint:sha-256 #{SDPFixtures.chrome_fingerprint()}
    a=setup:actpass
    a=mid:0
    a=sendrecv
    a=rtcp-mux
    a=rtpmap:111 opus/48000/2
    m=application 9 UDP/DTLS/SCTP webrtc-datachannel
    c=IN IP4 0.0.0.0
    a=ice-ufrag:cli1
    a=ice-pwd:clientpasswordpassword
    a=fingerprint:sha-256 #{SDPFixtures.chrome_fingerprint()}
    a=setup:actpass
    a=mid:1
    a=sctp-port:5000
    a=max-message-size:262144
    """

    answer =
      SDP.answer(offer,
        ice_ufrag: "svr1",
        ice_pwd: "serverpasswordpassword",
        fingerprint: SDPFixtures.chrome_fingerprint(),
        port: 10_000,
        ip: {192, 168, 0, 5}
      )

    assert answer =~ "a=group:BUNDLE 0 1\r\n"
    assert answer =~ "m=application 10000 UDP/DTLS/SCTP webrtc-datachannel\r\n"
    assert answer =~ "a=sctp-port:5000\r\n"
    assert answer =~ "a=mid:1\r\n"
  end

  test "normalize_codec accepts header strings" do
    assert SDP.normalize_codec("pcmu") == :pcmu
    assert SDP.normalize_codec("G722") == :g722
    assert SDP.normalize_codec("nope") == :opus
  end
end
