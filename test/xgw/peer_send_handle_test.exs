defmodule XGW.PeerSendHandleTest do
  use XGW.Test.Case

  alias XGW.{Listener, Peer}
  alias XGW.Peer.{SendHandle, Turn}
  alias XGW.Test.{SDPFixtures, StunFixtures, TurnFixtures}
  alias XMediaLib.{Rtp, Srtp, Stun}

  test "outbound_handle errors before media and ok after connect_dtls" do
    {peer, sock, client_ip, client_port, sk, ss} = media_ready_peer()

    assert {:error, :not_ready} = Peer.outbound_handle(peer)

    assert :ok = Peer.connect_dtls(peer, keys(sk, ss), {client_ip, client_port})
    assert_receive {:xgw, :dtls_connected, ^peer}
    drain_stun(sock)

    assert {:ok, %SendHandle{peer: ^peer, generation: gen}} = Peer.outbound_handle(peer)
    assert is_integer(gen) and gen >= 1

    :gen_udp.close(sock)
    assert :ok = Peer.close(peer)
  end

  test "SendHandle.send_rtp delivers SRTP without Peer GenServer.call" do
    {peer, sock, client_ip, client_port, sk, ss} = media_ready_peer()

    assert :ok = Peer.connect_dtls(peer, keys(sk, ss), {client_ip, client_port})
    assert_receive {:xgw, :dtls_connected, ^peer}
    drain_stun(sock)

    assert {:ok, handle} = Peer.outbound_handle(peer)

    rtp = sample_rtp(7, 42, "fast")
    assert :ok = SendHandle.send_rtp(handle, 7, rtp)
    assert {:ok, {_ip, _port, wire}} = :gen_udp.recv(sock, 2000)

    ctx = Srtp.new_ctx(7, :aes_cm, :hmac_sha1, sk, ss, 10)
    assert {:ok, %Rtp{payload: "fast", ssrc: 7}, _} = Srtp.decrypt(wire, ctx)

    :gen_udp.close(sock)
    assert :ok = Peer.close(peer)
  end

  test "invalidate on close makes subsequent hot send fail" do
    {peer, sock, client_ip, client_port, sk, ss} = media_ready_peer()

    assert :ok = Peer.connect_dtls(peer, keys(sk, ss), {client_ip, client_port})
    assert_receive {:xgw, :dtls_connected, ^peer}
    drain_stun(sock)

    assert {:ok, handle} = Peer.outbound_handle(peer)
    assert :ok = Peer.close(peer)

    assert {:error, :not_ready} = Peer.outbound_handle(peer)
    assert {:error, _} = SendHandle.send_rtp(handle, 7, sample_rtp(7, 1, "x"))

    :gen_udp.close(sock)
  end

  test "send_rtp call and SendHandle share outbound ROC" do
    {peer, sock, client_ip, client_port, sk, ss} = media_ready_peer()

    assert :ok = Peer.connect_dtls(peer, keys(sk, ss), {client_ip, client_port})
    assert_receive {:xgw, :dtls_connected, ^peer}
    drain_stun(sock)

    assert {:ok, handle} = Peer.outbound_handle(peer)

    assert :ok = Peer.send_rtp(peer, 7, sample_rtp(7, 1, "a"))
    assert {:ok, {_, _, wire1}} = :gen_udp.recv(sock, 2000)

    assert :ok = SendHandle.send_rtp(handle, 7, sample_rtp(7, 2, "b"))
    assert {:ok, {_, _, wire2}} = :gen_udp.recv(sock, 2000)

    ctx = Srtp.new_ctx(7, :aes_cm, :hmac_sha1, sk, ss, 10)
    assert {:ok, %Rtp{payload: "a"}, ctx2} = Srtp.decrypt(wire1, ctx)
    assert {:ok, %Rtp{payload: "b"}, _} = Srtp.decrypt(wire2, ctx2)

    :gen_udp.close(sock)
    assert :ok = Peer.close(peer)
  end

  test "ICE-TCP selected path has no hot UDP handle" do
    {peer, sock, client_ip, client_port, sk, ss} = media_ready_peer()

    :sys.replace_state(peer, fn state ->
      %{state | selected_transport: :tcp}
    end)

    assert :ok = Peer.connect_dtls(peer, keys(sk, ss), {client_ip, client_port})
    assert_receive {:xgw, :dtls_connected, ^peer}

    assert {:error, :use_genserver} = Peer.outbound_handle(peer)
    assert {:error, :use_genserver} =
             SendHandle.send_rtp(%SendHandle{peer: peer, generation: 1}, 7, sample_rtp(7, 1, "x"))

    :gen_udp.close(sock)
    assert :ok = Peer.close(peer)
  end

  test "publish_passthrough delivers sync without SRTP" do
    parent = self()

    assert :ok =
             SendHandle.publish_passthrough(parent, {__MODULE__, :passthrough_deliver, parent})

    assert {:ok, handle} = SendHandle.fetch(parent)
    rtp = sample_rtp(9, 1, "plain")
    assert :ok = SendHandle.send_rtp(handle, 9, rtp)
    assert_receive {:got, 9, %Rtp{payload: "plain", ssrc: 9}}
    assert :ok = SendHandle.invalidate(parent)
  end

  def passthrough_deliver(sink, ssrc, rtp) do
    send(sink, {:got, ssrc, rtp})
    :ok
  end

  test "TURN channel hot path wraps ChannelData to TURN server" do
    mapped = {{203, 0, 113, 91}, 41_004}
    {:ok, inbox} = Agent.start_link(fn -> {0, nil} end)
    {turn_port, _pid, turn_sock} = TurnFixtures.start_echo_server(mapped: mapped, counter: inbox)
    on_exit(fn -> :gen_udp.close(turn_sock) end)

    assert {:ok, listener} =
             Listener.start_link(
               ip: {127, 0, 0, 1},
               port: 0,
               turn_servers: ["turn:127.0.0.1:#{turn_port}"],
               relay_only: true
             )

    on_exit(fn -> if Process.alive?(listener), do: GenServer.stop(listener) end)
    Process.unlink(listener)

    assert {:ok, peer} =
             Peer.start_supervised(handler: self(), listener: listener, ice_lite: false)

    assert {:ok, [relay_line | _]} = Peer.prefetch_relay_candidates(peer)
    fp = Listener.local_fingerprint(listener)

    client_ufrag = "chromeUfrag"
    server_ufrag = "xgwufrag"
    server_pwd = "xgwpasswordxgwpasswordx"

    assert :ok =
             Peer.apply_descriptions(
               peer,
               SDPFixtures.minimal_offer(client_ufrag, "chromePasswordchromePassword"),
               SDPFixtures.xgw_full_answer(fp,
                 ufrag: server_ufrag,
                 pwd: server_pwd,
                 candidate_lines: [relay_line]
               )
             )

    assert_receive {:xgw, :local_candidates_complete, ^peer}, 5_000

    {:ok, client} = :gen_udp.open(0, [:binary, active: false])
    on_exit(fn -> :gen_udp.close(client) end)
    {:ok, client_port} = :inet.port(client)

    assert :ok =
             Peer.add_remote_candidate(peer, %{
               candidate: "candidate:2 1 UDP 1853824767 127.0.0.1 #{client_port} typ host",
               mid: "0"
             })

    assert :ok = Peer.add_remote_candidate(peer, %{end_of_candidates: true, mid: "0"})

    binding =
      StunFixtures.connectivity_check_wire(
        pwd: server_pwd,
        username: "#{server_ufrag}:#{client_ufrag}",
        use_candidate: true
      )

    Peer.deliver(
      peer,
      :stun,
      turn_data_ind({{127, 0, 0, 1}, client_port}, binding, 42),
      %{from: {{127, 0, 0, 1}, turn_port}}
    )

    assert_receive {:xgw, :ice_connected, ^peer}, 2_000

    sk = :crypto.strong_rand_bytes(16)
    ss = :crypto.strong_rand_bytes(14)
    assert :ok = Peer.connect_dtls(peer, keys(sk, ss), {{127, 0, 0, 1}, client_port})
    assert_receive {:xgw, :dtls_connected, ^peer}

    # Force Send Indication path, then late ChannelBind must republish the hot handle.
    :sys.replace_state(peer, fn state ->
      cleared = %{state | peer_channels: %{}, turn_channels: %{}}
      _ = SendHandle.publish_peer_state(self(), cleared)
      Turn.maybe_create_permission(cleared, cleared.ice)
    end)

    prior = Agent.get(inbox, fn {n, _} -> n end)
    assert {:ok, handle} = Peer.outbound_handle(peer)
    assert :ok = SendHandle.send_rtp(handle, 7, sample_rtp(7, 3, "turn"))

    frame =
      Enum.reduce_while(1..40, nil, fn _, _ ->
        case Agent.get(inbox, & &1) do
          {n, bin} when n > prior and is_binary(bin) ->
            {:halt, bin}

          _ ->
            Process.sleep(25)
            {:cont, nil}
        end
      end)

    assert is_binary(frame)
    assert <<channel::16, len::16, payload::binary>> = frame
    assert channel >= 0x4000 and channel <= 0x7FFF
    app = binary_part(payload, 0, len)

    ctx = Srtp.new_ctx(7, :aes_cm, :hmac_sha1, sk, ss, 10)
    assert {:ok, %Rtp{payload: "turn", ssrc: 7}, _} = Srtp.decrypt(app, ctx)

    assert :ok = Peer.close(peer)
  end

  defp media_ready_peer do
    assert {:ok, listener} = Listener.start_link(ip: {127, 0, 0, 1}, port: 0)
    on_exit(fn -> if Process.alive?(listener), do: GenServer.stop(listener) end)
    Process.unlink(listener)

    port = Listener.port(listener)
    server_pwd = "serverpasswordpassword"
    client_ufrag = "cli1"

    assert {:ok, peer} =
             Peer.start_supervised(handler: self(), listener: listener, ice_lite: true)

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

    sk = :crypto.strong_rand_bytes(16)
    ss = :crypto.strong_rand_bytes(14)

    {peer, sock, client_ip, client_port, sk, ss}
  end

  defp keys(sk, ss) do
    key = :crypto.strong_rand_bytes(16)
    salt = :crypto.strong_rand_bytes(14)
    {key, salt, sk, ss}
  end

  defp sample_rtp(ssrc, seq, payload) do
    %Rtp{
      padding: 0,
      marker: 0,
      payload_type: 111,
      sequence_number: seq,
      timestamp: 99,
      ssrc: ssrc,
      csrcs: [],
      extension: nil,
      payload: payload
    }
  end

  defp drain_stun(sock) do
    assert {:ok, {_ip, _port, stun_reply}} = :gen_udp.recv(sock, 1000)
    assert <<0::2, _::6, _::binary>> = stun_reply
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

  defp turn_data_ind(peer, data, tid) do
    Stun.encode(%Stun{
      class: :indication,
      method: 7,
      fingerprint: false,
      transactionid: tid,
      attrs: %{xor_peer_address: peer, data: data}
    })
  end
end
