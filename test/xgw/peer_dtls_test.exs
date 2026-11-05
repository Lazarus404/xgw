defmodule XGW.PeerDTLSTest do
  use XGW.Test.Case

  alias XGW.{Peer, SRTPSession}
  alias XGW.Test.SDPFixtures
  alias XMediaLib.{Rtp, Srtp}

  test "mock ICE and DTLS then decrypt synthetic SRTP to handler" do
    handler = self()

    assert {:ok, peer} = Peer.start_supervised(handler: handler, ice_lite: true)

    assert :ok =
             Peer.apply_descriptions(
               peer,
               SDPFixtures.minimal_offer("cli1", "clientpasswordpassword"),
               SDPFixtures.xgw_answer(SDPFixtures.chrome_fingerprint(),
                 ufrag: "svr1",
                 pwd: "serverpasswordpassword"
               )
             )

    from = {{127, 0, 0, 1}, 5000}
    assert :ok = Peer.connect_ice(peer, from)
    assert_receive {:xgw, :ice_connected, ^peer}
    assert :dtls_wait = Peer.phase(peer)

    key = :crypto.strong_rand_bytes(16)
    salt = :crypto.strong_rand_bytes(14)
    assert :ok = Peer.connect_dtls(peer, {key, salt, key, salt})
    assert_receive {:xgw, :dtls_connected, ^peer}
    assert :media = Peer.phase(peer)

    rtp = %Rtp{
      padding: 0,
      marker: 0,
      payload_type: 111,
      sequence_number: 1,
      timestamp: 2,
      ssrc: 99,
      csrcs: [],
      extension: nil,
      payload: "audio"
    }

    ctx = Srtp.new_ctx(99, :aes_cm, :hmac_sha1, key, salt, 10)
    {:ok, enc, _} = Srtp.encrypt(rtp, ctx)

    Peer.deliver(peer, :rtp, enc, %{from: from})
    assert_receive {:xgw, :rtp, ^peer, %Rtp{ssrc: 99, payload_type: 111}, meta}
    assert meta.from == from
    assert meta.mid == nil

    assert :ok = Peer.close(peer)
    assert_receive {:xgw, :closed, ^peer, :normal}
  end

  test "RTCP then RTP on same SSRC decrypts after connect_dtls (Chrome order)" do
    handler = self()
    assert {:ok, peer} = Peer.start_supervised(handler: handler, ice_lite: true)

    assert :ok =
             Peer.apply_descriptions(
               peer,
               SDPFixtures.minimal_offer("cli1", "clientpasswordpassword"),
               SDPFixtures.xgw_answer(SDPFixtures.chrome_fingerprint(),
                 ufrag: "svr1",
                 pwd: "serverpasswordpassword"
               )
             )

    from = {{127, 0, 0, 1}, 5001}
    assert :ok = Peer.connect_ice(peer, from)
    assert_receive {:xgw, :ice_connected, ^peer}

    key = :crypto.strong_rand_bytes(16)
    salt = :crypto.strong_rand_bytes(14)
    assert :ok = Peer.connect_dtls(peer, {key, salt, key, salt})
    assert_receive {:xgw, :dtls_connected, ^peer}

    ssrc = 1_606_442_007

    sr = %XMediaLib.Rtcp.Sr{
      ssrc: ssrc,
      ntp: 3_987_053_123_265_456_7890,
      timestamp: 987_654_321,
      packets: 1,
      octets: 100,
      rblocks: []
    }

    rtcp = %XMediaLib.Rtcp{payloads: [sr]}
    ctx_rtcp = Srtp.new_ctx(ssrc, :aes_cm, :hmac_sha1, key, salt, 10)
    {:ok, rtcp_wire, _} = Srtp.encrypt(rtcp, ctx_rtcp)
    Peer.deliver(peer, :rtcp, rtcp_wire, %{from: from})
    refute_receive {:xgw, :rtp, _, _, _}, 50

    rtp = %Rtp{
      padding: 0,
      marker: 0,
      payload_type: 111,
      sequence_number: 1,
      timestamp: 2,
      ssrc: ssrc,
      csrcs: [],
      extension: nil,
      payload: "opus-ish"
    }

    ctx_rtp = Srtp.new_ctx(ssrc, :aes_cm, :hmac_sha1, key, salt, 10)
    {:ok, rtp_wire, _} = Srtp.encrypt(rtp, ctx_rtp)
    Peer.deliver(peer, :rtp, rtp_wire, %{from: from})

    assert_receive {:xgw, :rtp, ^peer, %Rtp{ssrc: ^ssrc, payload_type: 111, payload: "opus-ish"}, meta}
    assert meta.from == from

    assert :ok = Peer.close(peer)
    assert_receive {:xgw, :closed, ^peer, :normal}
  end

  test "SRTPSession keys flow through connect_dtls" do
    handler = self()
    assert {:ok, peer} = Peer.start_supervised(handler: handler)
    assert :ok = Peer.connect_ice(peer, {{127, 0, 0, 1}, 5000})
    assert_receive {:xgw, :ice_connected, ^peer}

    keys = {:crypto.strong_rand_bytes(16), :crypto.strong_rand_bytes(14),
            :crypto.strong_rand_bytes(16), :crypto.strong_rand_bytes(14)}

    assert :ok = Peer.connect_dtls(peer, keys)
    assert_receive {:xgw, :dtls_connected, ^peer}
    assert :media = Peer.phase(peer)

    session = SRTPSession.new(keys)
    assert %SRTPSession{client_key: ck} = session
    assert byte_size(ck) == 16

    assert :ok = Peer.close(peer)
    assert_receive {:xgw, :closed, ^peer, :normal}
  end
end
