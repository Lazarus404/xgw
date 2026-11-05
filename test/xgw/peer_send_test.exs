defmodule XGW.PeerSendTest do
  use XGW.Test.Case

  alias XGW.{Listener, Peer}
  alias XGW.Test.SDPFixtures
  alias XMediaLib.{Rtp, Srtp, Stun}

  test "send_rtp delivers SRTP to ICE-selected client address" do
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

    {:ok, sock} = :gen_udp.open(0, [:binary, active: false, reuseaddr: true, ip: {127, 0, 0, 1}])
    {:ok, {_client_ip, client_port}} = :inet.sockname(sock)
    client_ip = {127, 0, 0, 1}

    req = stun_binding(server_pwd, "svr1:#{client_ufrag}")
    assert :ok = :gen_udp.send(sock, {127, 0, 0, 1}, port, req)
    assert_receive {:xgw, :ice_connected, ^peer}, 2000

    key = :crypto.strong_rand_bytes(16)
    salt = :crypto.strong_rand_bytes(14)
    sk = :crypto.strong_rand_bytes(16)
    ss = :crypto.strong_rand_bytes(14)

    assert :ok = Peer.connect_dtls(peer, {key, salt, sk, ss}, {client_ip, client_port})
    assert_receive {:xgw, :dtls_connected, ^peer}

    # Drain STUN success response before waiting for RTP.
    assert {:ok, {_ip, _port, stun_reply}} = :gen_udp.recv(sock, 1000)
    assert <<0::2, _::6, _::binary>> = stun_reply

    rtp = %Rtp{
      padding: 0,
      marker: 0,
      payload_type: 111,
      sequence_number: 42,
      timestamp: 99,
      ssrc: 7,
      csrcs: [],
      extension: nil,
      payload: "echo"
    }

    assert :ok = Peer.send_rtp(peer, 7, rtp)
    assert {:ok, {_recv_ip, _recv_port, wire}} = :gen_udp.recv(sock, 2000)

    ctx = Srtp.new_ctx(7, :aes_cm, :hmac_sha1, sk, ss, 10)
    assert {:ok, %Rtp{payload: "echo", ssrc: 7}, _} = Srtp.decrypt(wire, ctx)

    :gen_udp.close(sock)
    assert :ok = Peer.close(peer)
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
