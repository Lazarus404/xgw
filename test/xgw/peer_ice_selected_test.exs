defmodule XGW.PeerIceSelectedTest do
  use XGW.Test.Case

  alias XGW.Peer
  alias XGW.Test.SDPFixtures
  alias XMediaLib.{Rtp, Srtp, Stun}

  test "STUN from a second address does not drop RTP from the first selected pair" do
    handler = self()

    assert {:ok, peer} =
             Peer.start_supervised(handler: handler, ice_lite: true)

    assert :ok =
             Peer.apply_descriptions(
               peer,
               SDPFixtures.minimal_offer("cli1", "clientpasswordpassword"),
               SDPFixtures.xgw_answer(SDPFixtures.chrome_fingerprint(),
                 ufrag: "svr1",
                 pwd: "serverpasswordpassword"
               )
             )

    first = {{127, 0, 0, 1}, 5000}
    second = {{192, 168, 0, 5}, 5001}

    assert :ok = Peer.connect_ice(peer, first)
    assert_receive {:xgw, :ice_connected, ^peer}

    key = :crypto.strong_rand_bytes(16)
    salt = :crypto.strong_rand_bytes(14)
    assert :ok = Peer.connect_dtls(peer, {key, salt, key, salt}, first)
    assert_receive {:xgw, :dtls_connected, ^peer}

    # Later check from another host address (multi-homed Chrome).
    req = consent_stun("serverpasswordpassword", "svr1:cli1")
    assert :ok = Peer.deliver(peer, :stun, req, %{from: second})

    state = :sys.get_state(peer)
    assert state.selected == first
    assert MapSet.member?(state.ice_ok_remotes, first)
    assert MapSet.member?(state.ice_ok_remotes, second)

    ctx = Srtp.new_ctx(42, :aes_cm, :hmac_sha1, key, salt, 10)

    rtp = %Rtp{
      padding: 0,
      marker: 0,
      payload_type: 111,
      sequence_number: 1,
      timestamp: 0,
      ssrc: 42,
      csrcs: [],
      extension: nil,
      payload: "hi"
    }

    {:ok, wire, _} = Srtp.encrypt(rtp, ctx)
    assert :ok = Peer.deliver(peer, :rtp, wire, %{from: first})
    assert_receive {:xgw, :rtp, ^peer, %Rtp{payload: "hi"}, _}, 500

    {:ok, wire2, _} = Srtp.encrypt(%{rtp | sequence_number: 2}, ctx)
    assert :ok = Peer.deliver(peer, :rtp, wire2, %{from: second})
    assert_receive {:xgw, :rtp, ^peer, %Rtp{sequence_number: 2}, _}, 500

    assert :ok = Peer.close(peer)
  end

  defp consent_stun(pwd, username) do
    %Stun{
      class: :request,
      method: :binding,
      transactionid: :erlang.unique_integer([:positive]),
      integrity: true,
      key: pwd,
      fingerprint: true,
      attrs: %{
        username: username,
        ice_controlling: <<1, 2, 3, 4, 5, 6, 7, 8>>
      }
    }
    |> Stun.encode()
  end
end
