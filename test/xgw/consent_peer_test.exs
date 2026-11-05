defmodule XGW.ConsentPeerTest do
  use XGW.Test.Case

  alias XGW.Peer
  alias XGW.Test.SDPFixtures
  alias XMediaLib.Stun

  test "inbound STUN request on selected pair refreshes consent" do
    handler = self()

    assert {:ok, peer} =
             Peer.start_supervised(
               handler: handler,
               ice_lite: true,
               consent_interval_ms: 5_000,
               consent_timeout_ms: 30_000
             )

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

    key = :crypto.strong_rand_bytes(16)
    salt = :crypto.strong_rand_bytes(14)
    assert :ok = Peer.connect_dtls(peer, {key, salt, key, salt}, from)
    assert_receive {:xgw, :dtls_connected, ^peer}

    req = consent_stun("serverpasswordpassword", "svr1:cli1")
    assert :ok = Peer.deliver(peer, :stun, req, %{from: from})

    send(peer, :consent_tick)
    refute_receive {:xgw, :closed, ^peer, :consent_failed}, 100

    assert :ok = Peer.close(peer)
    assert_peer_closed(peer, :normal)
  end

  test "inbound STUN binding success response refreshes consent" do
    handler = self()
    from = {{127, 0, 0, 1}, 5000}

    assert {:ok, peer} =
             Peer.start_supervised(
               handler: handler,
               ice_lite: true,
               consent_interval_ms: 60_000,
               consent_timeout_ms: 20
             )

    assert :ok =
             Peer.apply_descriptions(
               peer,
               SDPFixtures.minimal_offer("cli1", "clientpasswordpassword"),
               SDPFixtures.xgw_answer(SDPFixtures.chrome_fingerprint(),
                 ufrag: "svr1",
                 pwd: "serverpasswordpassword"
               )
             )

    assert :ok = Peer.connect_ice(peer, from)
    assert_receive {:xgw, :ice_connected, ^peer}

    key = :crypto.strong_rand_bytes(16)
    salt = :crypto.strong_rand_bytes(14)
    assert :ok = Peer.connect_dtls(peer, {key, salt, key, salt}, from)
    assert_receive {:xgw, :dtls_connected, ^peer}

    stale = System.monotonic_time(:millisecond) - 100

    :sys.replace_state(peer, fn s ->
      %{s | ice: Map.put(s.ice, :last_consent_at, stale)}
    end)

    success =
      %Stun{
        class: :success,
        method: :binding,
        transactionid: 42,
        integrity: true,
        key: "clientpasswordpassword",
        fingerprint: true,
        attrs: %{xor_mapped_address: from}
      }
      |> Stun.encode()

    assert :ok = Peer.deliver(peer, :stun, success, %{from: from})
    send(peer, :consent_tick)
    refute_receive {:xgw, :closed, ^peer, :consent_failed}, 100

    assert :ok = Peer.close(peer)
    assert_peer_closed(peer, :normal)
  end

  test "consent timeout closes peer with consent_failed" do
    handler = self()

    assert {:ok, peer} =
             Peer.start_supervised(
               handler: handler,
               ice_lite: true,
               consent_interval_ms: 10,
               consent_timeout_ms: 20
             )

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

    key = :crypto.strong_rand_bytes(16)
    salt = :crypto.strong_rand_bytes(14)
    assert :ok = Peer.connect_dtls(peer, {key, salt, key, salt}, from)
    assert_receive {:xgw, :dtls_connected, ^peer}

    Process.sleep(30)
    send(peer, :consent_tick)

    assert_receive {:xgw, :closed, ^peer, :consent_failed}, 500
  end

  test "full mode inbound STUN on selected pair refreshes consent" do
    handler = self()

    assert {:ok, peer} =
             Peer.start_supervised(
               handler: handler,
               ice_lite: false,
               consent_interval_ms: 5_000,
               consent_timeout_ms: 30_000
             )

    assert :ok =
             Peer.apply_descriptions(
               peer,
               SDPFixtures.minimal_offer("cli1", "clientpasswordpassword"),
               SDPFixtures.xgw_full_answer(SDPFixtures.chrome_fingerprint(),
                 ufrag: "svr1",
                 pwd: "serverpasswordpassword"
               )
             )

    from = {{127, 0, 0, 1}, 5000}
    assert :ok = Peer.connect_ice(peer, from)
    assert_receive {:xgw, :ice_connected, ^peer}

    key = :crypto.strong_rand_bytes(16)
    salt = :crypto.strong_rand_bytes(14)
    assert :ok = Peer.connect_dtls(peer, {key, salt, key, salt}, from)
    assert_receive {:xgw, :dtls_connected, ^peer}

    req = consent_stun("serverpasswordpassword", "svr1:cli1")
    assert :ok = Peer.deliver(peer, :stun, req, %{from: from})

    send(peer, :consent_tick)
    refute_receive {:xgw, :closed, ^peer, :consent_failed}, 100

    assert :ok = Peer.close(peer)
    assert_peer_closed(peer, :normal)
  end

  test "full mode consent timeout closes peer with consent_failed" do
    handler = self()

    assert {:ok, peer} =
             Peer.start_supervised(
               handler: handler,
               ice_lite: false,
               consent_interval_ms: 10,
               consent_timeout_ms: 20
             )

    assert :ok =
             Peer.apply_descriptions(
               peer,
               SDPFixtures.minimal_offer("cli1", "clientpasswordpassword"),
               SDPFixtures.xgw_full_answer(SDPFixtures.chrome_fingerprint(),
                 ufrag: "svr1",
                 pwd: "serverpasswordpassword"
               )
             )

    from = {{127, 0, 0, 1}, 5000}
    assert :ok = Peer.connect_ice(peer, from)
    assert_receive {:xgw, :ice_connected, ^peer}

    key = :crypto.strong_rand_bytes(16)
    salt = :crypto.strong_rand_bytes(14)
    assert :ok = Peer.connect_dtls(peer, {key, salt, key, salt}, from)
    assert_receive {:xgw, :dtls_connected, ^peer}

    Process.sleep(30)
    send(peer, :consent_tick)

    assert_receive {:xgw, :closed, ^peer, :consent_failed}, 500
  end

  test "full mode binding success response refreshes consent" do
    handler = self()
    from = {{127, 0, 0, 1}, 5000}

    assert {:ok, peer} =
             Peer.start_supervised(
               handler: handler,
               ice_lite: false,
               consent_interval_ms: 60_000,
               consent_timeout_ms: 20
             )

    assert :ok =
             Peer.apply_descriptions(
               peer,
               SDPFixtures.minimal_offer("cli1", "clientpasswordpassword"),
               SDPFixtures.xgw_full_answer(SDPFixtures.chrome_fingerprint(),
                 ufrag: "svr1",
                 pwd: "serverpasswordpassword"
               )
             )

    assert :ok = Peer.connect_ice(peer, from)
    assert_receive {:xgw, :ice_connected, ^peer}

    key = :crypto.strong_rand_bytes(16)
    salt = :crypto.strong_rand_bytes(14)
    assert :ok = Peer.connect_dtls(peer, {key, salt, key, salt}, from)
    assert_receive {:xgw, :dtls_connected, ^peer}

    stale = System.monotonic_time(:millisecond) - 100

    :sys.replace_state(peer, fn s ->
      %{s | ice: Map.put(s.ice, :last_consent_at, stale)}
    end)

    success =
      %Stun{
        class: :success,
        method: :binding,
        transactionid: 42,
        integrity: true,
        key: "clientpasswordpassword",
        fingerprint: true,
        attrs: %{xor_mapped_address: from}
      }
      |> Stun.encode()

    assert :ok = Peer.deliver(peer, :stun, success, %{from: from})
    send(peer, :consent_tick)
    refute_receive {:xgw, :closed, ^peer, :consent_failed}, 100

    assert :ok = Peer.close(peer)
    assert_peer_closed(peer, :normal)
  end

  test "full mode ice_restart re-seeds remote and returns to checking" do
    assert {:ok, peer} = Peer.start_supervised(handler: self(), ice_lite: false)

    assert :ok =
             Peer.apply_descriptions(
               peer,
               SDPFixtures.minimal_offer("cli1", "clientpasswordpassword"),
               SDPFixtures.xgw_full_answer(SDPFixtures.chrome_fingerprint(),
                 ufrag: "svr1",
                 pwd: "serverpasswordpassword"
               )
             )

    from = {{127, 0, 0, 1}, 5000}
    assert :ok = Peer.connect_ice(peer, from)
    assert_receive {:xgw, :ice_connected, ^peer}

    assert :ok =
             Peer.ice_restart(peer, SDPFixtures.minimal_offer("cli2", "newpasswordpasswordnew"))

    assert Peer.phase(peer) == :ice_wait
    assert Peer.ice_phase(peer) in [:checking, :gathering]

    ice = :sys.get_state(peer).ice
    assert ice.remote_ice_ufrag == "cli2"

    assert :ok = Peer.close(peer)
    assert_peer_closed(peer, :normal)
  end

  test "lite mode ice_restart returns not_implemented" do
    assert {:ok, peer} = Peer.start_supervised(handler: self(), ice_lite: true)

    assert {:error, :not_implemented} =
             Peer.ice_restart(peer, SDPFixtures.minimal_offer("a", "b"))
  end

  defp consent_stun(pwd, username) do
    %Stun{
      class: :request,
      method: :binding,
      transactionid: 123,
      integrity: true,
      key: pwd,
      fingerprint: true,
      attrs: %{username: username}
    }
    |> Stun.encode()
  end
end
