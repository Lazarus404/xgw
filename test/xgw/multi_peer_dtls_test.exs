defmodule XGW.MultiPeerDTLSTest do
  use XGW.Test.Case

  alias XGW.{Certs, Listener, Peer}
  alias XGW.Test.SDPFixtures
  alias XMediaLib.Stun

  test "two peers on one listener reach media via distinct remotes" do
    assert {:ok, listener} = Listener.start_link(ip: {127, 0, 0, 1}, port: 0)
    on_exit(fn -> if Process.alive?(listener), do: GenServer.stop(listener) end)
    Process.unlink(listener)
    port = Listener.port(listener)

    handler = self()
    pwd = "serverpasswordpassword"

    assert {:ok, peer_a} =
             Peer.start_supervised(handler: handler, listener: listener, ice_lite: true)

    assert {:ok, peer_b} =
             Peer.start_supervised(handler: handler, listener: listener, ice_lite: true)

    assert :ok =
             SDPFixtures.apply_with_listener(
               peer_a,
               listener,
               "cliA",
               "clientpasswordpassword",
               "svrA",
               pwd
             )

    assert :ok =
             SDPFixtures.apply_with_listener(
               peer_b,
               listener,
               "cliB",
               "clientpasswordpassword",
               "svrB",
               pwd
             )

    {:ok, sock_a} = :gen_udp.open(0, [:binary, active: false, ip: {127, 0, 0, 1}])
    {:ok, sock_b} = :gen_udp.open(0, [:binary, active: false, ip: {127, 0, 0, 1}])
    on_exit(fn -> :gen_udp.close(sock_a) end)
    on_exit(fn -> :gen_udp.close(sock_b) end)
    {:ok, port_a} = :inet.port(sock_a)
    {:ok, port_b} = :inet.port(sock_b)
    from_a = {{127, 0, 0, 1}, port_a}
    from_b = {{127, 0, 0, 1}, port_b}

    assert :ok = :gen_udp.send(sock_a, {127, 0, 0, 1}, port, stun_binding(pwd, "svrA:cliA"))
    assert_receive {:xgw, :ice_connected, ^peer_a}, 2000
    refute_receive {:xgw, :ice_connected, ^peer_b}, 100

    assert :ok = :gen_udp.send(sock_b, {127, 0, 0, 1}, port, stun_binding(pwd, "svrB:cliB"))
    assert_receive {:xgw, :ice_connected, ^peer_b}, 2000

    key = :crypto.strong_rand_bytes(16)
    salt = :crypto.strong_rand_bytes(14)
    assert :ok = Peer.connect_dtls(peer_a, {key, salt, key, salt}, from_a)
    assert_receive {:xgw, :dtls_connected, ^peer_a}
    assert :media = Peer.phase(peer_a)
    assert :dtls_wait = Peer.phase(peer_b)

    assert :ok = Peer.connect_dtls(peer_b, {key, salt, key, salt}, from_b)
    assert_receive {:xgw, :dtls_connected, ^peer_b}
    assert :media = Peer.phase(peer_b)

    assert :ok = Peer.close(peer_a)
    assert :ok = Peer.close(peer_b)
  end

  @tag :external
  test "two peers complete real DTLS handshakes on one listener" do
    assert {:ok, listener} = Listener.start_link(port: 0)
    on_exit(fn -> if Process.alive?(listener), do: GenServer.stop(listener) end)
    Process.unlink(listener)
    port = Listener.port(listener)
    fp_server = Listener.local_fingerprint(listener)
    handler = self()
    pwd = "serverpasswordpassword"

    {cert_a, key_a} = Certs.ensure!(Path.join(System.tmp_dir!(), "xgw-multi-dtls-a"))
    {cert_b, key_b} = Certs.ensure!(Path.join(System.tmp_dir!(), "xgw-multi-dtls-b"))
    fp_a = Certs.fingerprint(cert_a)
    fp_b = Certs.fingerprint(cert_b)

    assert {:ok, peer_a} =
             Peer.start_supervised(handler: handler, listener: listener, ice_lite: true)

    assert :ok =
             Peer.apply_descriptions(
               peer_a,
               SDPFixtures.minimal_offer("cliA", "clientpasswordpassword", fingerprint: fp_a),
               SDPFixtures.xgw_answer(fp_server, ufrag: "svrA", pwd: pwd)
             )

    {:ok, sock_a} = :gen_udp.open(0, [:binary, active: false])
    assert :ok = :gen_udp.send(sock_a, {127, 0, 0, 1}, port, stun_binding(pwd, "svrA:cliA"))
    assert_receive {:xgw, :ice_connected, ^peer_a}, 2000
    :gen_udp.close(sock_a)

    client_a =
      Task.async(fn ->
        {:ok, sock} =
          :ssl.connect(~c"127.0.0.1", port,
            verify: :verify_none,
            certfile: String.to_charlist(cert_a),
            keyfile: String.to_charlist(key_a),
            protocol: :dtls,
            versions: [:"dtlsv1.2"],
            use_srtp: %{protection_profiles: [<<0, 1>>]},
            mode: :binary,
            active: false
          )

        receive do
          :close -> :ssl.close(sock)
        after
          15_000 -> :ssl.close(sock)
        end
      end)

    assert_receive {:xgw, :dtls_connected, ^peer_a}, 10_000
    send(client_a.pid, :close)
    Task.await(client_a, 5_000)

    assert {:ok, peer_b} =
             Peer.start_supervised(handler: handler, listener: listener, ice_lite: true)

    assert :ok =
             Peer.apply_descriptions(
               peer_b,
               SDPFixtures.minimal_offer("cliB", "clientpasswordpassword", fingerprint: fp_b),
               SDPFixtures.xgw_answer(fp_server, ufrag: "svrB", pwd: pwd)
             )

    {:ok, sock_b} = :gen_udp.open(0, [:binary, active: false])
    {:ok, port_b} = :inet.port(sock_b)
    assert :ok = :gen_udp.send(sock_b, {127, 0, 0, 1}, port, stun_binding(pwd, "svrB:cliB"))
    assert_receive {:xgw, :ice_connected, ^peer_b}, 2000
    :gen_udp.close(sock_b)

    # Reuse ICE UDP port so by_from demux hits peer_b (two peers, no fallback).
    client_b =
      Task.async(fn ->
        {:ok, sock} =
          :ssl.connect(~c"127.0.0.1", port,
            verify: :verify_none,
            certfile: String.to_charlist(cert_b),
            keyfile: String.to_charlist(key_b),
            protocol: :dtls,
            versions: [:"dtlsv1.2"],
            use_srtp: %{protection_profiles: [<<0, 1>>]},
            mode: :binary,
            active: false,
            ip: {127, 0, 0, 1},
            port: port_b
          )

        receive do
          :close -> :ssl.close(sock)
        after
          15_000 -> :ssl.close(sock)
        end
      end)

    assert_receive {:xgw, :dtls_connected, ^peer_b}, 10_000
    send(client_b.pid, :close)
    Task.await(client_b, 5_000)

    assert :media = Peer.phase(peer_a)
    assert :media = Peer.phase(peer_b)
    assert :ok = Peer.close(peer_a)
    assert :ok = Peer.close(peer_b)
  end

  defp stun_binding(pwd, username) do
    Stun.encode(%Stun{
      class: :request,
      method: :binding,
      transactionid: 1_234_567_890,
      integrity: true,
      key: pwd,
      fingerprint: true,
      attrs: %{
        username: username,
        priority: <<0, 0, 0, 1>>,
        ice_controlling: <<1, 2, 3, 4, 5, 6, 7, 8>>
      }
    })
  end
end
