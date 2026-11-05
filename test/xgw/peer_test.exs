defmodule XGW.PeerTest do
  use XGW.Test.Case

  alias XGW.{Listener, Peer}
  alias XGW.Test.SDPFixtures
  alias XMediaLib.{Rtp, Srtp}

  test "start, ICE/DTLS phases, SRTP delivery, and close" do
    handler = self()

    assert {:ok, listener} = Listener.start_link(port: 0)
    on_exit(fn -> if Process.alive?(listener), do: GenServer.stop(listener) end)
    Process.unlink(listener)

    assert {:ok, peer} =
             Peer.start_supervised(handler: handler, listener: listener, ice_lite: true)

    assert :ice_wait = Peer.phase(peer)

    assert :ok =
             SDPFixtures.apply_with_listener(
               peer,
               listener,
               "cli1",
               "clientpasswordpassword",
               "svr1",
               "serverpasswordpassword"
             )

    from = {{127, 0, 0, 1}, 4000}
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
      ssrc: 1,
      csrcs: [],
      extension: nil,
      payload: <<>>
    }

    ctx = Srtp.new_ctx(1, :aes_cm, :hmac_sha1, key, salt, 10)
    {:ok, enc, _} = Srtp.encrypt(rtp, ctx)
    Peer.deliver(peer, :rtp, enc, %{from: from})
    assert_receive {:xgw, :rtp, ^peer, %Rtp{}, meta}
    assert meta.from == from
    assert is_integer(meta.arrival_us)
    assert :ok = Peer.send_rtp(peer, 1, rtp)

    assert {:error, :missing_fingerprint} = Peer.apply_descriptions(peer, "offer", "answer")

    assert {:error, :invalid_candidate} = Peer.add_remote_candidate(peer, %{candidate: "bad"})

    assert {:error, :encrypt_failed} = Peer.send_rtcp(peer, <<>>)

    assert :ok = Peer.close(peer)
    assert_receive {:xgw, :closed, ^peer, :normal}
    refute Process.alive?(peer)
  end

  test "deliver preserves an existing arrival_us stamp" do
    handler = self()

    assert {:ok, listener} = Listener.start_link(port: 0)
    on_exit(fn -> if Process.alive?(listener), do: GenServer.stop(listener) end)
    Process.unlink(listener)

    assert {:ok, peer} =
             Peer.start_supervised(handler: handler, listener: listener, ice_lite: true)

    assert :ok =
             SDPFixtures.apply_with_listener(
               peer,
               listener,
               "cli2",
               "clientpasswordpassword",
               "svr2",
               "serverpasswordpassword"
             )

    from = {{127, 0, 0, 1}, 4001}
    assert :ok = Peer.connect_ice(peer, from)
    assert_receive {:xgw, :ice_connected, ^peer}

    key = :crypto.strong_rand_bytes(16)
    salt = :crypto.strong_rand_bytes(14)
    assert :ok = Peer.connect_dtls(peer, {key, salt, key, salt})
    assert_receive {:xgw, :dtls_connected, ^peer}

    rtp = %Rtp{
      padding: 0,
      marker: 0,
      payload_type: 111,
      sequence_number: 2,
      timestamp: 3,
      ssrc: 2,
      csrcs: [],
      extension: nil,
      payload: <<>>
    }

    ctx = Srtp.new_ctx(2, :aes_cm, :hmac_sha1, key, salt, 10)
    {:ok, enc, _} = Srtp.encrypt(rtp, ctx)
    Peer.deliver(peer, :rtp, enc, %{from: from, arrival_us: 42})
    assert_receive {:xgw, :rtp, ^peer, %Rtp{}, meta}
    assert meta.arrival_us == 42
  end

  test "close is idempotent when process already stopped" do
    assert {:ok, peer} = Peer.start_supervised(handler: self())
    assert :ok = Peer.close(peer)
    assert :ok = Peer.close(peer)
  end

  test "close does not respawn under PeerSupervisor" do
    before = length(DynamicSupervisor.which_children(XGW.PeerSupervisor))
    assert {:ok, peer} = Peer.start_supervised(handler: self())
    assert :ok = Peer.close(peer)
    Process.sleep(50)
    refute Process.alive?(peer)
    assert length(DynamicSupervisor.which_children(XGW.PeerSupervisor)) == before
  end
end
