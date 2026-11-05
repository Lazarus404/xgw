defmodule XGW.ApplyDescriptionsTest do
  use XGW.Test.Case

  alias XGW.{Listener, Peer}
  alias XGW.Test.SDPFixtures

  test "apply_descriptions seeds ICE remote candidates from offer" do
    assert {:ok, peer} = Peer.start_supervised(handler: self(), ice_lite: true)

    assert :ok =
             Peer.apply_descriptions(
               peer,
               SDPFixtures.chrome_offer(),
               SDPFixtures.xgw_answer(SDPFixtures.chrome_fingerprint())
             )

    %{ice: %{remote_candidates: cands}} = :sys.get_state(peer)
    assert length(cands) >= 1
    assert hd(cands).type in ["host", "srflx", "relay"]

    assert :ok = Peer.close(peer)
    assert_receive {:xgw, :closed, ^peer, :normal}
  end

  test "apply_descriptions stores config and ice credentials" do
    assert {:ok, listener} = Listener.start_link(port: 0)
    on_exit(fn -> if Process.alive?(listener), do: GenServer.stop(listener) end)
    Process.unlink(listener)

    assert {:ok, peer} =
             Peer.start_supervised(handler: self(), listener: listener, ice_lite: true)

    assert :ok =
             SDPFixtures.apply_with_listener(
               peer,
               listener,
               "cli1",
               "clientpasswordpassword",
               "svr1",
               "serverpasswordpassword"
             )

    assert :ok = Peer.close(peer)
    assert_receive {:xgw, :closed, ^peer, :normal}
  end

  test "rejects local fingerprint mismatch against listener cert" do
    assert {:ok, listener} = Listener.start_link(port: 0)
    on_exit(fn -> if Process.alive?(listener), do: GenServer.stop(listener) end)
    Process.unlink(listener)

    assert {:ok, peer} =
             Peer.start_supervised(handler: self(), listener: listener, ice_lite: true)

    assert {:error, :local_fingerprint_mismatch} =
             Peer.apply_descriptions(
               peer,
               SDPFixtures.minimal_offer("cli1", "clientpasswordpassword"),
               SDPFixtures.xgw_answer(SDPFixtures.chrome_fingerprint())
             )

    assert :ok = Peer.close(peer)
    assert_receive {:xgw, :closed, ^peer, :normal}
  end

  test "add_remote_candidate appends validated candidate" do
    assert {:ok, peer} = Peer.start_supervised(handler: self(), ice_lite: true)

    assert :ok =
             Peer.apply_descriptions(
               peer,
               SDPFixtures.minimal_offer("cli1", "clientpasswordpassword"),
               SDPFixtures.xgw_answer(SDPFixtures.chrome_fingerprint())
             )

    # Without listener, local fingerprint check is skipped
    assert :ok =
             Peer.add_remote_candidate(peer, %{
               candidate: "candidate:1 1 UDP 2122260223 192.0.2.10 50000 typ host"
             })

    assert {:error, :invalid_candidate} =
             Peer.add_remote_candidate(peer, %{candidate: "bad"})

    assert :ok = Peer.close(peer)
    assert_receive {:xgw, :closed, ^peer, :normal}
  end

  test "add_remote_candidate on closed peer returns not_connected" do
    assert {:ok, peer} = Peer.start_supervised(handler: self())
    assert :ok = Peer.close(peer)
    assert_receive {:xgw, :closed, ^peer, :normal}, 500

    assert {:error, :not_connected} =
             Peer.add_remote_candidate(peer, %{
               candidate: "candidate:1 1 UDP 2122260223 192.0.2.10 50000 typ host"
             })
  end
end
