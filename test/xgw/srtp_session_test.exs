defmodule XGW.SRTPSessionTest do
  use ExUnit.Case, async: true

  alias XGW.SRTPSession
  alias XMediaLib.{Rtcp, Rtp, Srtp}

  @client_key <<0xE1F97A0D3E018BE0D64FA32C06DE4139::size(128)>>
  @client_salt <<0x0EC675AD498AFEEBB6960B3AABE6::size(112)>>
  @server_key <<0xA1B2C3D4E5F60718293A4B5C6D7E8F90::size(128)>>
  @server_salt <<0x112233445566778899AABBCCDDEE::size(112)>>
  @payload <<"pseudorandomness is the next best thing">>
  @ssrc 1_549_931_929

  @rtp %Rtp{
    padding: 0,
    marker: 0,
    payload_type: 110,
    sequence_number: 23_738,
    timestamp: 1_349_000_677,
    ssrc: @ssrc,
    csrcs: [],
    extension: nil,
    payload: @payload
  }

  test "decrypt round-trip updates per-SSRC context" do
    ctx = Srtp.new_ctx(@ssrc, :aes_cm, :hmac_sha1, @client_key, @client_salt, 10)
    {:ok, enc, ctx1} = Srtp.encrypt(@rtp, ctx)

    session = SRTPSession.new({@client_key, @client_salt, @server_key, @server_salt})

    assert {:ok, %Rtp{} = dec, session2} = SRTPSession.decrypt(session, :rtp, enc)
    assert dec.payload == @payload
    assert map_size(session2.decrypt_contexts) == 1

    {:ok, enc2, _} = Srtp.encrypt(%{@rtp | sequence_number: 23_739}, ctx1)
    assert {:ok, %Rtp{sequence_number: 23_739}, _} = SRTPSession.decrypt(session2, :rtp, enc2)
  end

  test "decrypt round-trip with RFC 3550 header extension" do
    rtp = %{
      @rtp
      | marker: 1,
        extension: %Rtp.Extension{
          type: 0xBEDE,
          payload: <<0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00>>
        }
    }

    ctx = Srtp.new_ctx(@ssrc, :aes_cm, :hmac_sha1, @client_key, @client_salt, 10)
    {:ok, enc, _} = Srtp.encrypt(rtp, ctx)
    session = SRTPSession.new({@client_key, @client_salt, @server_key, @server_salt})

    assert {:ok, %Rtp{} = dec, _} = SRTPSession.decrypt(session, :rtp, enc)
    assert dec.payload == @payload
    assert dec.marker == 1
  end

  test "encrypt round-trip with server keys simulates browser receive" do
    session = SRTPSession.new({@client_key, @client_salt, @server_key, @server_salt})

    assert {:ok, wire, session2} = SRTPSession.encrypt(session, :rtp, @rtp)
    assert is_binary(wire)
    assert map_size(session2.encrypt_contexts) == 1

    ctx = Srtp.new_ctx(@ssrc, :aes_cm, :hmac_sha1, @server_key, @server_salt, 10)
    assert {:ok, %Rtp{} = dec, _} = Srtp.decrypt(wire, ctx)
    assert dec.payload == @payload
  end

  test "encrypt updates per-SSRC encrypt context" do
    session = SRTPSession.new({@client_key, @client_salt, @server_key, @server_salt})

    assert {:ok, _wire, session2} = SRTPSession.encrypt(session, :rtp, @rtp)

    assert {:ok, _wire2, session3} =
             SRTPSession.encrypt(session2, :rtp, %{@rtp | sequence_number: 23_739})

    assert map_size(session3.encrypt_contexts) == 1
  end

  test "RTCP encrypt round-trip" do
    sr = %Rtcp.Sr{
      ssrc: @ssrc,
      ntp: 3_987_053_123_265_456_7890,
      timestamp: 987_654_321,
      packets: 1234,
      octets: 567_890,
      rblocks: []
    }

    rtcp = %Rtcp{payloads: [sr]}
    session = SRTPSession.new({@client_key, @client_salt, @server_key, @server_salt})

    assert {:ok, wire, session2} = SRTPSession.encrypt(session, :rtcp, rtcp)
    assert is_binary(wire)
    assert map_size(session2.encrypt_contexts) == 1

    ctx = Srtp.new_ctx(@ssrc, :aes_cm, :hmac_sha1, @server_key, @server_salt, 10)
    assert {:ok, dec, _} = Srtp.decrypt(wire, ctx)
    assert [%Rtcp.Sr{ssrc: @ssrc}] = dec.payloads
  end

  test "RTCP decrypt then RTP decrypt on same SSRC use separate contexts" do
    sr = %Rtcp.Sr{
      ssrc: @ssrc,
      ntp: 3_987_053_123_265_456_7890,
      timestamp: 987_654_321,
      packets: 1234,
      octets: 567_890,
      rblocks: []
    }

    rtcp = %Rtcp{payloads: [sr]}
    ctx_rtcp = Srtp.new_ctx(@ssrc, :aes_cm, :hmac_sha1, @client_key, @client_salt, 10)
    {:ok, rtcp_wire, _} = Srtp.encrypt(rtcp, ctx_rtcp)

    ctx_rtp = Srtp.new_ctx(@ssrc, :aes_cm, :hmac_sha1, @client_key, @client_salt, 10)
    {:ok, rtp_wire, _} = Srtp.encrypt(@rtp, ctx_rtp)

    session = SRTPSession.new({@client_key, @client_salt, @server_key, @server_salt})

    assert {:ok, %Rtcp{}, session2} = SRTPSession.decrypt(session, :rtcp, rtcp_wire)
    assert map_size(session2.decrypt_contexts) == 1

    assert {:ok, %Rtp{} = dec, session3} = SRTPSession.decrypt(session2, :rtp, rtp_wire)
    assert dec.payload == @payload
    assert map_size(session3.decrypt_contexts) == 2
  end

  test "decrypt failure logs once per kind" do
    session = SRTPSession.new({@client_key, @client_salt, @server_key, @server_salt})
    assert {:error, session2} = SRTPSession.decrypt(session, :rtp, <<128, 1>>)
    assert MapSet.member?(session2.fail_logged, :rtp)
    assert {:error, ^session2} = SRTPSession.decrypt(session2, :rtp, <<128, 1>>)
    assert {:error, session3} = SRTPSession.decrypt(session2, :rtcp, <<128, 200, 0, 0>>)
    assert MapSet.member?(session3.fail_logged, :rtcp)
  end

  test "decrypt success does not clear fail_logged so later failures stay quiet" do
    import ExUnit.CaptureLog

    ctx = Srtp.new_ctx(@ssrc, :aes_cm, :hmac_sha1, @client_key, @client_salt, 10)
    {:ok, good, _} = Srtp.encrypt(@rtp, ctx)
    session = SRTPSession.new({@client_key, @client_salt, @server_key, @server_salt})

    assert {:error, session2} = SRTPSession.decrypt(session, :rtp, <<128, 1>>)
    assert MapSet.member?(session2.fail_logged, :rtp)

    assert {:ok, %Rtp{}, session3} = SRTPSession.decrypt(session2, :rtp, good)
    assert MapSet.member?(session3.fail_logged, :rtp)

    log =
      capture_log(fn ->
        assert {:error, session4} = SRTPSession.decrypt(session3, :rtp, <<128, 1>>)
        assert MapSet.member?(session4.fail_logged, :rtp)
      end)

    refute log =~ "xgw SRTP decrypt failed"
  end
end
