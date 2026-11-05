defmodule XGW.SpikeTest do
  @moduledoc false
  use ExUnit.Case

  @tag :external
  test "binding success may include ICE-CONTROLLED attribute" do
    alias XMediaLib.Stun

    pwd = "serverpasswordpassword"
    tie = <<1, 2, 3, 4, 5, 6, 7, 8>>

    reply =
      %Stun{
        class: :success,
        method: :binding,
        transactionid: 9_876_543_210,
        integrity: true,
        key: pwd,
        fingerprint: true,
        attrs: %{
          xor_mapped_address: {{192, 168, 0, 2}, 53_628},
          ice_controlled: tie
        }
      }
      |> Stun.encode()

    assert {:ok, %Stun{attrs: %{ice_controlled: ^tie}}} = Stun.decode(reply, pwd)
  end

  @tag :external
  test "spike modules load and SDP answer shape" do
    offer = """
    v=0
    o=- 0 0 IN IP4 127.0.0.1
    s=-
    t=0 0
    m=audio 9 UDP/TLS/RTP/SAVPF 111
    c=IN IP4 0.0.0.0
    a=rtpmap:111 opus/48000/2
    a=mid:0
    """

    answer =
      XGW.Spike.SDP.answer(offer,
        ice_ufrag: "abcd",
        ice_pwd: "efghijklmnopqrstuv",
        fingerprint: "00:11",
        ip: {127, 0, 0, 1},
        ips: [{127, 0, 0, 1}, {192, 168, 0, 6}],
        port: 10_000
      )

    assert answer =~ "a=candidate:1 1 udp 2130706431 127.0.0.1 10000"
    assert answer =~ "a=candidate:2 1 udp 2130706431 192.168.0.6 10000"

    assert answer =~ "a=setup:passive"
    refute answer =~ "a=ice-lite"
    assert answer =~ "a=rtcp-mux"
    assert answer =~ "a=rtpmap:111 opus/48000/2"
    assert answer =~ "a=fingerprint:sha-256 00:11"
    assert answer =~ "a=candidate:"
    refute answer =~ "end-of-candidates"
    assert String.ends_with?(answer, "\r\n")

    assert {"abcd", "efghijklmnopqrstuv"} ==
             XGW.Spike.SDP.parse_ice("""
             v=0
             a=ice-ufrag:zzzz
             a=ice-pwd:wrong
             m=audio 9 UDP/TLS/RTP/SAVPF 111
             a=ice-ufrag:abcd
             a=ice-pwd:efghijklmnopqrstuv
             """)
  end

  @tag :external
  test "ICE connectivity-check STUN verifies with server ice-pwd" do
    alias XMediaLib.Stun

    server_ufrag = "svr1"
    server_pwd = "serverpasswordpassword"
    client_ufrag = "cli1"

    req = %Stun{
      class: :request,
      method: :binding,
      transactionid: 1_234_567_890_123,
      integrity: true,
      key: server_pwd,
      fingerprint: true,
      attrs: %{
        username: "#{server_ufrag}:#{client_ufrag}",
        priority: <<0, 0, 0, 1>>
      }
    }

    wire = Stun.encode(req)
    assert {:ok, %Stun{method: :binding}} = Stun.decode(wire, server_pwd)
  end

  @tag :external
  test "Chrome goog_network_info STUN attribute decodes" do
    alias XMediaLib.Stun

    pwd = "serverpasswordpassword"

    req = %Stun{
      class: :request,
      method: :binding,
      transactionid: 99_001,
      integrity: true,
      key: pwd,
      fingerprint: true,
      attrs: %{
        goog_network_info: <<0, 1, 0, 2>>
      }
    }

    wire = Stun.encode(req)
    assert {:ok, %Stun{attrs: %{goog_network_info: <<0, 1, 0, 2>>}}} = Stun.decode(wire, pwd)
  end
end
