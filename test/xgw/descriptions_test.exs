defmodule XGW.DescriptionsTest do
  use ExUnit.Case, async: true
  doctest XGW.Descriptions

  alias XGW.Descriptions
  alias XGW.Test.SDPFixtures
  alias XMediaLib.SDP.Fingerprint

  test "builds config from chrome offer and synthetic answer" do
    offer = SDPFixtures.chrome_offer()
    answer = SDPFixtures.xgw_answer(SDPFixtures.chrome_fingerprint())

    assert {:ok, config} = Descriptions.build(offer, answer, ice_lite: true)

    assert config.bundle_mids == ["0", "1", "2"]
    assert config.remote_fingerprint == %Fingerprint{
             algorithm: "sha-256",
             value: SDPFixtures.chrome_fingerprint()
           }
    assert config.setup == :passive
    assert config.ice.local_ufrag == "xgwufrag"
    assert config.ice.remote_ufrag == "chromeUfrag"
    assert config.ice.local_setup == :passive
    assert config.ice.remote_setup == :actpass
    assert config.ssrc_to_mid[1001] == "0"
    assert Map.has_key?(config.media_by_mid, "0")
    assert length(config.remote_candidates) >= 1
    # Answer has no application m-line, so SCTP is not negotiated.
    assert config.sctp == nil
  end

  test "builds config from datachannel-only offer and answer" do
    offer = """
    v=0
    o=- 1 2 IN IP4 127.0.0.1
    s=-
    t=0 0
    a=group:BUNDLE 0
    m=application 9 UDP/DTLS/SCTP webrtc-datachannel
    c=IN IP4 0.0.0.0
    a=ice-ufrag:cli1
    a=ice-pwd:clientpasswordpassword
    a=fingerprint:sha-256 #{SDPFixtures.chrome_fingerprint()}
    a=setup:actpass
    a=mid:0
    a=sctp-port:5000
    a=max-message-size:262144
    """

    answer = """
    v=0
    o=- 0 0 IN IP4 127.0.0.1
    s=-
    t=0 0
    a=group:BUNDLE 0
    a=ice-lite
    m=application 10000 UDP/DTLS/SCTP webrtc-datachannel
    c=IN IP4 127.0.0.1
    a=ice-ufrag:svr1
    a=ice-pwd:serverpasswordpassword
    a=fingerprint:sha-256 #{SDPFixtures.chrome_fingerprint()}
    a=setup:passive
    a=mid:0
    a=sctp-port:5000
    a=max-message-size:262144
    """

    assert {:ok, config} = Descriptions.build(offer, answer, ice_lite: true)
    assert config.bundle_mids == ["0"]
    assert config.setup == :passive

    assert config.sctp == %{
             remote_port: 5000,
             local_port: 5000,
             max_message_size: 262_144
           }
  end

  test "builds sctp info when offer and answer include application m-line" do
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

    answer = """
    v=0
    o=- 0 0 IN IP4 127.0.0.1
    s=-
    t=0 0
    a=group:BUNDLE 0 1
    m=audio 10000 UDP/TLS/RTP/SAVPF 111
    c=IN IP4 127.0.0.1
    a=ice-ufrag:svr1
    a=ice-pwd:serverpasswordpassword
    a=fingerprint:sha-256 #{SDPFixtures.chrome_fingerprint()}
    a=setup:passive
    a=mid:0
    a=recvonly
    a=rtcp-mux
    a=rtpmap:111 opus/48000/2
    m=application 10000 UDP/DTLS/SCTP webrtc-datachannel
    c=IN IP4 127.0.0.1
    a=ice-ufrag:svr1
    a=ice-pwd:serverpasswordpassword
    a=fingerprint:sha-256 #{SDPFixtures.chrome_fingerprint()}
    a=setup:passive
    a=mid:1
    a=sctp-port:5000
    a=max-message-size:262144
    """

    assert {:ok, config} = Descriptions.build(offer, answer, ice_lite: true)

    assert config.sctp == %{
             remote_port: 5000,
             local_port: 5000,
             max_message_size: 262_144
           }
  end

  test "full mode builds local_setup and remote_setup in ice map" do
    offer = SDPFixtures.minimal_offer("cli", "clientpasswordpassword")
    host = "candidate:1 1 UDP 2130706431 127.0.0.1 5000 typ host"

    answer =
      SDPFixtures.xgw_full_answer(SDPFixtures.chrome_fingerprint(), host_candidate: host)

    assert {:ok, config} = Descriptions.build(offer, answer, ice_lite: false)
    assert config.ice.local_setup == :passive
    assert config.ice.remote_setup == :actpass
    assert length(config.local_candidates) == 1
    assert hd(config.local_candidates).type == "host"
  end

  test "accepts Firefox-style session-level fingerprint" do
    offer = """
    v=0
    o=mozilla...THIS_IS_SDPARTA-99.0 1 0 IN IP4 0.0.0.0
    s=-
    t=0 0
    a=fingerprint:sha-256 #{SDPFixtures.chrome_fingerprint()}
    a=group:BUNDLE 0 1
    m=audio 9 UDP/TLS/RTP/SAVPF 109
    c=IN IP4 0.0.0.0
    a=sendonly
    a=ice-pwd:firefoxpasswordfirefoxpwd
    a=ice-ufrag:ffufrag1
    a=mid:0
    a=rtcp-mux
    a=rtpmap:109 opus/48000/2
    a=setup:actpass
    m=application 9 UDP/DTLS/SCTP webrtc-datachannel
    c=IN IP4 0.0.0.0
    a=ice-pwd:firefoxpasswordfirefoxpwd
    a=ice-ufrag:ffufrag1
    a=mid:1
    a=setup:actpass
    a=sctp-port:5000
    """

    answer = """
    v=0
    o=- 0 0 IN IP4 127.0.0.1
    s=-
    t=0 0
    a=group:BUNDLE 0 1
    m=audio 10000 UDP/TLS/RTP/SAVPF 109
    c=IN IP4 127.0.0.1
    a=ice-ufrag:svr1
    a=ice-pwd:serverpasswordpassword
    a=fingerprint:sha-256 #{SDPFixtures.chrome_fingerprint()}
    a=setup:passive
    a=mid:0
    a=recvonly
    a=rtcp-mux
    a=rtpmap:109 opus/48000/2
    m=application 10000 UDP/DTLS/SCTP webrtc-datachannel
    c=IN IP4 127.0.0.1
    a=ice-ufrag:svr1
    a=ice-pwd:serverpasswordpassword
    a=fingerprint:sha-256 #{SDPFixtures.chrome_fingerprint()}
    a=setup:passive
    a=mid:1
    a=sctp-port:5000
    """

    assert {:ok, config} = Descriptions.build(offer, answer, ice_lite: false)
    assert config.remote_fingerprint.value == SDPFixtures.chrome_fingerprint()
    assert config.ice.remote_ufrag == "ffufrag1"
    assert config.sctp.remote_port == 5000
  end

  test "rejects invalid sdp" do
    assert {:error, :missing_fingerprint} = Descriptions.build("not sdp", "also not")
  end

  test "rejects missing fingerprint" do
    offer = SDPFixtures.minimal_offer("a", "b", fingerprint: "")
    answer = SDPFixtures.xgw_answer(SDPFixtures.chrome_fingerprint())

    assert {:error, :missing_fingerprint} = Descriptions.build(offer, answer)
  end

  test "rejects invalid setup for ice-lite" do
    offer = SDPFixtures.minimal_offer("a", "passwordpasswordpassword")
    answer = SDPFixtures.xgw_answer(SDPFixtures.chrome_fingerprint())

    bad_answer =
      answer
      |> String.replace("a=setup:passive", "a=setup:active")

    assert {:error, :invalid_setup} = Descriptions.build(offer, bad_answer, ice_lite: true)
  end

  test "fingerprints_match? is case-insensitive" do
    a = %Fingerprint{algorithm: "sha-256", value: "aa:bb:cc"}
    b = %Fingerprint{algorithm: "SHA-256", value: "AA:BB:CC"}
    assert Descriptions.fingerprints_match?(a, b)
  end
end
