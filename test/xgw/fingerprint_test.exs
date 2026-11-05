defmodule XGW.FingerprintTest do
  use XGW.Test.Case

  alias XGW.{Certs, DTLS, Listener, Peer}
  alias XGW.Test.SDPFixtures
  alias XMediaLib.{Stun, SDP.Fingerprint}

  @moduletag :external

  test "listener local_fingerprint matches certfile" do
    assert {:ok, listener} = Listener.start_link(port: 0)
    on_exit(fn -> if Process.alive?(listener), do: GenServer.stop(listener) end)
    Process.unlink(listener)

    fp = Listener.local_fingerprint(listener)
    assert is_binary(fp)
    assert String.match?(fp, ~r/^[0-9A-F]{2}(:[0-9A-F]{2}){31}$/)
  end

  test "verify_fingerprint matches client cert from DTLS handshake" do
    assert {:ok, listener} = Listener.start_link(port: 0)
    on_exit(fn -> if Process.alive?(listener), do: GenServer.stop(listener) end)
    Process.unlink(listener)

    listen_sock = Listener.listen_sock(listener)
    port = Listener.port(listener)
    client_dir = Path.join(System.tmp_dir!(), "xgw-fp-test-client")
    {client_cert, client_key} = Certs.ensure!(client_dir)
    expected = %Fingerprint{algorithm: "sha-256", value: Certs.fingerprint(client_cert)}

    client_task =
      Task.async(fn ->
        {:ok, client_sock} =
          :ssl.connect(~c"127.0.0.1", port,
            verify: :verify_none,
            certfile: String.to_charlist(client_cert),
            keyfile: String.to_charlist(client_key),
            protocol: :dtls,
            versions: [:"dtlsv1.2"],
            use_srtp: %{protection_profiles: [<<0, 1>>]}
          )

        client_sock
      end)

    assert {:ok, server_sock} = DTLS.handshake(listen_sock)
    client_sock = Task.await(client_task, 5_000)

    assert DTLS.verify_fingerprint(server_sock, expected)

    wrong = %Fingerprint{algorithm: "sha-256", value: SDPFixtures.chrome_fingerprint()}
    refute DTLS.verify_fingerprint(server_sock, wrong)

    :ssl.close(client_sock)
    :ssl.close(server_sock)
  end

  test "peer closes on remote DTLS fingerprint mismatch" do
    assert {:ok, listener} = Listener.start_link(ip: {127, 0, 0, 1}, port: 0)
    on_exit(fn -> if Process.alive?(listener), do: GenServer.stop(listener) end)
    Process.unlink(listener)
    port = Listener.port(listener)

    handler = self()
    server_pwd = "serverpasswordpassword"
    client_ufrag = "cli1"

    assert {:ok, peer} =
             Peer.start_supervised(handler: handler, listener: listener, ice_lite: true)

    assert :ok =
             SDPFixtures.apply_with_listener(
               peer,
               listener,
               client_ufrag,
               "clientpasswordpassword",
               "svr1",
               server_pwd
             )

    {:ok, sock} = :gen_udp.open(0, [:binary, active: false])
    req = stun_binding(server_pwd, "svr1:#{client_ufrag}")
    assert :ok = :gen_udp.send(sock, {127, 0, 0, 1}, port, req)
    assert_receive {:xgw, :ice_connected, ^peer}, 2000

    client_dir = Path.join(System.tmp_dir!(), "xgw-fp-mismatch-client")
    {client_cert, client_key} = Certs.ensure!(client_dir)

    ref = Process.monitor(peer)

    client_task =
      Task.async(fn ->
        :ssl.connect(~c"127.0.0.1", port,
          verify: :verify_none,
          certfile: String.to_charlist(client_cert),
          keyfile: String.to_charlist(client_key),
          protocol: :dtls,
          versions: [:"dtlsv1.2"],
          use_srtp: %{protection_profiles: [<<0, 1>>]}
        )
      end)

    assert_receive {:xgw, :closed, ^peer, :fingerprint_mismatch}, 5000
    assert_receive {:DOWN, ^ref, :process, ^peer, _}, 1000
    refute_receive {:xgw, :dtls_connected, ^peer}, 200

    Task.shutdown(client_task, :brutal_kill)
    :gen_udp.close(sock)
  end

  defp stun_binding(pwd, username) do
    %Stun{
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
    }
    |> Stun.encode()
  end
end
