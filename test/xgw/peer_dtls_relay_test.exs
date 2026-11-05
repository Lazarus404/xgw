defmodule XGW.PeerDtlsRelayTest do
  use XGW.Test.Case

  alias XGW.{DTLS.Transport, Listener, Peer}
  alias XGW.Test.{SDPFixtures, StunFixtures, TurnFixtures}
  alias XMediaLib.Stun

  test "queues DTLS during ice_wait and flushes after ICE connect via TURN Data Indication" do
    mapped = {{203, 0, 113, 77}, 41_002}
    {turn_port, _pid, turn_sock} = TurnFixtures.start_echo_server(mapped: mapped)
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

    dtls_hello = <<22, 0xFE, 0xFD, 1, 2, 3, 4, 5, 6, 7, 8>>

    Peer.deliver(
      peer,
      :stun,
      turn_data_ind({{127, 0, 0, 1}, client_port}, dtls_hello, 41),
      %{from: {{127, 0, 0, 1}, turn_port}}
    )

    assert :sys.get_state(peer).phase == :ice_wait
    assert :sys.get_state(peer).pending_dtls != []

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
    assert :sys.get_state(peer).phase == :dtls_wait
    assert :sys.get_state(peer).pending_dtls == []

    udp = Listener.udp_sock(listener)
    term = :persistent_term.get({Transport, udp})
    assert term.pending != [] or is_pid(term.owner)

    assert :ok = Peer.close(peer)
  end

  test "send_wire after relay ICE uses TURN Send Indication" do
    mapped = {{203, 0, 113, 88}, 41_003}
    {:ok, counter} = Agent.start_link(fn -> 0 end)
    {turn_port, _pid, turn_sock} = TurnFixtures.start_echo_server(mapped: mapped, counter: counter)
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

    key = :crypto.strong_rand_bytes(16)
    salt = :crypto.strong_rand_bytes(14)
    assert :ok = Peer.connect_dtls(peer, {key, salt, key, salt}, {{127, 0, 0, 1}, client_port})
    assert_receive {:xgw, :dtls_connected, ^peer}

    mid = Agent.get(counter, & &1)

    rtp = <<0x80, 111, 0, 1, 0, 0, 0, 2, 0, 0, 3, 0xE9, 1, 2, 3, 4>>
    assert :ok = Peer.send_rtp(peer, 1001, rtp)

    assert wait_send_count(counter, mid)

    assert :ok = Peer.close(peer)
  end

  defp wait_send_count(counter, prior, attempts \\ 40) do
    count = Agent.get(counter, & &1)

    cond do
      count > prior ->
        true

      attempts <= 0 ->
        flunk("expected TURN relay send after send_rtp, counter=#{count} prior=#{prior}")

      true ->
        Process.sleep(25)
        wait_send_count(counter, prior, attempts - 1)
    end
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
