defmodule XGW.PeerFullTest do
  use XGW.Test.Case

  alias XGW.{ICE, Listener, Peer}
  alias XGW.ICE.{Full, Gather}
  alias XGW.Test.{SDPFixtures, StunFixtures, TurnFixtures}

  @tag :external
  test "full-mode peer completes ICE on USE-CANDIDATE connectivity check" do
    assert {:ok, listener} = Listener.start_link(ip: {127, 0, 0, 1}, port: 0)
    on_exit(fn -> if Process.alive?(listener), do: GenServer.stop(listener) end)
    Process.unlink(listener)
    port = Listener.port(listener)
    fp = Listener.local_fingerprint(listener)

    client_ufrag = "chromeUfrag"
    server_ufrag = "xgwufrag"
    server_pwd = "xgwpasswordxgwpasswordx"

    assert {:ok, peer} =
             Peer.start_supervised(handler: self(), listener: listener, ice_lite: false)

    assert :ok =
             Peer.apply_descriptions(
               peer,
               SDPFixtures.chrome_offer(),
               SDPFixtures.xgw_full_answer(fp,
                 ufrag: server_ufrag,
                 pwd: server_pwd,
                 host_candidate: Listener.host_candidate_line(listener)
               )
             )

    assert Peer.ice_phase(peer) == :checking
    assert Peer.phase(peer) == :ice_wait

    {:ok, sock} = :gen_udp.open(0, [:binary, active: false])
    {:ok, local_port} = :inet.port(sock)

    assert :ok =
             Peer.add_remote_candidate(peer, %{
               candidate:
                 "candidate:2 1 UDP 1853824767 127.0.0.1 #{local_port} typ host",
               mid: "0"
             })

    req =
      XGW.Test.StunFixtures.connectivity_check_wire(
        pwd: server_pwd,
        username: "#{server_ufrag}:#{client_ufrag}",
        use_candidate: true
      )

    assert :ok = :gen_udp.send(sock, {127, 0, 0, 1}, port, req)

    assert_receive {:xgw, :ice_connected, ^peer}, 2000
    assert Peer.ice_phase(peer) == :completed
    assert Peer.phase(peer) == :dtls_wait

    :gen_udp.close(sock)
    assert :ok = Peer.close(peer)
    assert_receive {:xgw, :closed, ^peer, :normal}
  end

  test "trickle remote during checking does not reset active outbound check" do
    assert {:ok, listener} = Listener.start_link(ip: {127, 0, 0, 1}, port: 0)
    on_exit(fn -> if Process.alive?(listener), do: GenServer.stop(listener) end)
    Process.unlink(listener)
    fp = Listener.local_fingerprint(listener)

    server_ufrag = "xgwufrag"
    server_pwd = "xgwpasswordxgwpasswordx"

    assert {:ok, peer} =
             Peer.start_supervised(handler: self(), listener: listener, ice_lite: false)

    assert :ok =
             Peer.apply_descriptions(
               peer,
               SDPFixtures.chrome_offer(),
               SDPFixtures.xgw_full_answer(fp,
                 ufrag: server_ufrag,
                 pwd: server_pwd,
                 host_candidate: Listener.host_candidate_line(listener)
               )
             )

    assert Peer.ice_phase(peer) == :checking
    Process.sleep(Full.check_ta_ms() + 20)

    ice = :sys.get_state(peer).ice
    in_progress = Enum.find(ice.checklist, &(&1.state == :in_progress))
    assert in_progress
    tid = in_progress.transaction_id

    assert :ok =
             Peer.add_remote_candidate(peer, %{
               candidate: "candidate:3 1 UDP 2122260223 192.0.2.30 50002 typ host",
               mid: "0"
             })

    ice = :sys.get_state(peer).ice
    active = Enum.find(ice.checklist, &(&1.transaction_id == tid))
    assert active.state == :in_progress
    assert length(ice.checklist) >= 2

    assert :ok = Peer.close(peer)
    assert_receive {:xgw, :closed, ^peer, :normal}
  end

  test "lite peer ice_phase reports completed" do
    assert {:ok, peer} = Peer.start_supervised(handler: self(), ice_lite: true)

    assert :ok =
             Peer.apply_descriptions(
               peer,
               SDPFixtures.minimal_offer("cli", "clientpasswordpassword"),
               SDPFixtures.xgw_answer(SDPFixtures.chrome_fingerprint())
             )

    assert Peer.ice_phase(peer) == :completed
    assert :ok = Peer.close(peer)
    assert_receive {:xgw, :closed, ^peer, :normal}
  end

  test "full mode apply_descriptions rejects unsupported ICE setup" do
    assert {:ok, peer} = Peer.start_supervised(handler: self(), ice_lite: false)

    offer =
      SDPFixtures.minimal_offer("cli", "clientpasswordpassword")
      |> String.replace("a=setup:actpass", "a=setup:active")

    assert {:error, :unsupported_setup} =
             Peer.apply_descriptions(
               peer,
               offer,
               SDPFixtures.xgw_full_answer(SDPFixtures.chrome_fingerprint())
             )

    assert :ok = Peer.close(peer)
    assert_receive {:xgw, :closed, ^peer, :normal}
  end

  test "full mode emits local_candidates_complete when no gather tasks" do
    assert {:ok, listener} = Listener.start_link(ip: {127, 0, 0, 1}, port: 0)
    on_exit(fn -> if Process.alive?(listener), do: GenServer.stop(listener) end)
    Process.unlink(listener)
    fp = Listener.local_fingerprint(listener)

    assert {:ok, peer} =
             Peer.start_supervised(handler: self(), listener: listener, ice_lite: false)

    assert :ok =
             Peer.apply_descriptions(
               peer,
               SDPFixtures.chrome_offer(),
               SDPFixtures.xgw_full_answer(fp,
                 host_candidate: Listener.host_candidate_line(listener)
               )
             )

    assert_receive {:xgw, :local_candidates_complete, ^peer}

    assert :ok = Peer.close(peer)
    assert_receive {:xgw, :closed, ^peer, :normal}
  end

  test "relay Task DOWN :normal before result still delivers local_candidate" do
    assert {:ok, listener} = Listener.start_link(ip: {127, 0, 0, 1}, port: 0)
    on_exit(fn -> if Process.alive?(listener), do: GenServer.stop(listener) end)
    Process.unlink(listener)
    fp = Listener.local_fingerprint(listener)

    assert {:ok, peer} =
             Peer.start_supervised(handler: self(), listener: listener, ice_lite: false)

    assert :ok =
             Peer.apply_descriptions(
               peer,
               SDPFixtures.chrome_offer(),
               SDPFixtures.xgw_full_answer(fp,
                 host_candidate: Listener.host_candidate_line(listener)
               )
             )

    assert_receive {:xgw, :local_candidates_complete, ^peer}

    ref = make_ref()
    cand = Gather.build_relay({{203, 0, 113, 99}, 49_999})

    allocation = %{
      turn_server: {{127, 0, 0, 1}, 3478},
      relay: {{203, 0, 113, 99}, 49_999},
      lifetime_s: 600,
      username: "",
      realm: "",
      nonce: "",
      integrity_key: <<>>
    }

    :sys.replace_state(peer, fn state ->
      %{
        state
        | relay_task: %Task{ref: ref, pid: self(), owner: self(), mfa: {__MODULE__, :__test__, 0}},
          local_gather_complete?: false
      }
    end)

    # Successful Tasks emit DOWN :normal and {ref, result} with no order guarantee.
    send(peer, {:DOWN, ref, :process, self(), :normal})
    send(peer, {ref, [%{candidate: cand, allocation: allocation}]})

    assert_receive {:xgw, :local_candidate, ^peer, %{candidate: line, mid: "0"}}, 1_000
    assert line =~ "typ relay"
    assert_receive {:xgw, :local_candidates_complete, ^peer}, 1_000

    assert :ok = Peer.close(peer)
    assert_receive {:xgw, :closed, ^peer, :normal}
  end

  test "post-apply srflx trickle delivers local_candidate and grows local_candidates" do
    mapped = {{203, 0, 113, 50}, 54_321}
    {stun_port, _stun_pid, stun_sock} = StunFixtures.start_echo_server(mapped: mapped)
    on_exit(fn -> :gen_udp.close(stun_sock) end)

    assert {:ok, listener} =
             Listener.start_link(
               ip: {127, 0, 0, 1},
               port: 0,
               stun_servers: ["stun:127.0.0.1:#{stun_port}"]
             )

    on_exit(fn -> if Process.alive?(listener), do: GenServer.stop(listener) end)
    Process.unlink(listener)
    fp = Listener.local_fingerprint(listener)

    assert {:ok, peer} =
             Peer.start_supervised(handler: self(), listener: listener, ice_lite: false)

    assert :ok =
             Peer.apply_descriptions(
               peer,
               SDPFixtures.chrome_offer(),
               SDPFixtures.xgw_full_answer(fp,
                 host_candidate: Listener.host_candidate_line(listener)
               )
             )

    assert Peer.ice_phase(peer) in [:checking, :gathering]
    assert length(Peer.local_candidates(peer)) == 1

    assert_receive {:xgw, :local_candidate, ^peer, %{candidate: line, mid: "0"}}, 5_000
    assert line =~ "typ srflx"
    assert line =~ "raddr"
    assert line =~ "rport"
    assert length(Peer.local_candidates(peer)) >= 2
    assert_receive {:xgw, :local_candidates_complete, ^peer}, 1000
    refute_receive {:xgw, :ice_connected, ^peer}, 200
    assert Peer.ice_phase(peer) in [:checking, :gathering]

    assert :ok = Peer.close(peer)
    assert_receive {:xgw, :closed, ^peer, :normal}
  end

  test "post-apply relay trickle delivers local_candidate with typ relay" do
    mapped = {{203, 0, 113, 99}, 49_999}
    {turn_port, _pid, turn_sock} = TurnFixtures.start_echo_server(mapped: mapped)
    on_exit(fn -> :gen_udp.close(turn_sock) end)

    assert {:ok, listener} =
             Listener.start_link(
               ip: {127, 0, 0, 1},
               port: 0,
               turn_servers: ["turn:127.0.0.1:#{turn_port}"]
             )

    on_exit(fn -> if Process.alive?(listener), do: GenServer.stop(listener) end)
    Process.unlink(listener)
    fp = Listener.local_fingerprint(listener)

    assert {:ok, peer} =
             Peer.start_supervised(handler: self(), listener: listener, ice_lite: false)

    assert :ok =
             Peer.apply_descriptions(
               peer,
               SDPFixtures.chrome_offer(),
               SDPFixtures.xgw_full_answer(fp,
                 host_candidate: Listener.host_candidate_line(listener)
               )
             )

    assert_receive {:xgw, :local_candidate, ^peer, %{candidate: line, mid: "0"}}, 5_000
    assert line =~ "typ relay"
    assert length(Peer.local_candidates(peer)) >= 2
    assert Peer.ice_phase(peer) in [:checking, :gathering]

    assert :ok = Peer.close(peer)
    assert_receive {:xgw, :closed, ^peer, :normal}
  end

  test "relay_only listener accepts answer with relay-only locals" do
    relay_line = Gather.build_relay({{203, 0, 113, 99}, 49_999}) |> ICE.candidate_line()

    assert {:ok, listener} =
             Listener.start_link(
               ip: {127, 0, 0, 1},
               port: 0,
               turn_servers: ["turn:127.0.0.1:3478"],
               relay_only: true
             )

    on_exit(fn -> if Process.alive?(listener), do: GenServer.stop(listener) end)
    Process.unlink(listener)
    fp = Listener.local_fingerprint(listener)

    assert {:ok, peer} =
             Peer.start_supervised(handler: self(), listener: listener, ice_lite: false)

    assert :ok =
             Peer.apply_descriptions(
               peer,
               SDPFixtures.chrome_offer(),
               SDPFixtures.xgw_full_answer(fp, candidate_lines: [relay_line])
             )

    assert hd(Peer.local_candidates(peer)).type == "relay"
    assert Peer.ice_phase(peer) in [:checking, :gathering]

    assert :ok = Peer.close(peer)
    assert_receive {:xgw, :closed, ^peer, :normal}
  end

  test "prefetch_relay_candidates covers relay_only answer without second Allocate" do
    mapped = {{203, 0, 113, 88}, 40_002}
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
    fp = Listener.local_fingerprint(listener)

    assert {:ok, peer} =
             Peer.start_supervised(handler: self(), listener: listener, ice_lite: false)

    assert {:ok, [relay_line | _]} = Peer.prefetch_relay_candidates(peer)
    assert relay_line =~ "typ relay"

    assert :ok =
             Peer.apply_descriptions(
               peer,
               SDPFixtures.chrome_offer(),
               SDPFixtures.xgw_full_answer(fp, candidate_lines: [relay_line])
             )

    assert hd(Peer.local_candidates(peer)).type == "relay"
    assert_receive {:xgw, :local_candidates_complete, ^peer}, 5_000

    assert :ok = Peer.close(peer)
    assert_receive {:xgw, :closed, ^peer, :normal}
  end

  test "relay_only outbound check uses TURN Send Indication" do
    mapped = {{203, 0, 113, 99}, 49_999}
    {:ok, counter} = Agent.start_link(fn -> 0 end)
    {turn_port, _pid, turn_sock} = TurnFixtures.start_echo_server(mapped: mapped, counter: counter)
    on_exit(fn -> :gen_udp.close(turn_sock) end)

    relay_line = Gather.build_relay(mapped) |> ICE.candidate_line()

    assert {:ok, listener} =
             Listener.start_link(
               ip: {127, 0, 0, 1},
               port: 0,
               turn_servers: ["turn:127.0.0.1:#{turn_port}"],
               relay_only: true
             )

    on_exit(fn -> if Process.alive?(listener), do: GenServer.stop(listener) end)
    Process.unlink(listener)
    fp = Listener.local_fingerprint(listener)

    client_ufrag = "chromeUfrag"
    server_ufrag = "xgwufrag"
    server_pwd = "xgwpasswordxgwpasswordx"

    assert {:ok, peer} =
             Peer.start_supervised(handler: self(), listener: listener, ice_lite: false)

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
    assert :sys.get_state(peer).turn_allocations != []

    {:ok, client} = :gen_udp.open(0, [:binary, active: false])
    {:ok, client_port} = :inet.port(client)

    assert :ok =
             Peer.add_remote_candidate(peer, %{
               candidate:
                 "candidate:2 1 UDP 1853824767 127.0.0.1 #{client_port} typ host",
               mid: "0"
             })

    stun_wire =
      Enum.reduce_while(1..200, nil, fn _, _ ->
        case :gen_udp.recv(client, 2048, 25) do
          {:ok, data} when is_binary(data) ->
            {:halt, data}

          {:ok, {_ip, _port, data}} when is_binary(data) ->
            {:halt, data}

          {:error, :timeout} ->
            {:cont, nil}
        end
      end)

    assert is_binary(stun_wire) and byte_size(stun_wire) > 0
    assert Agent.get(counter, & &1) >= 1

    req =
      StunFixtures.connectivity_check_wire(
        pwd: server_pwd,
        username: "#{server_ufrag}:#{client_ufrag}",
        use_candidate: true
      )

    assert :ok = :gen_udp.send(client, {127, 0, 0, 1}, Listener.port(listener), req)
    assert_receive {:xgw, :ice_connected, ^peer}, 2000
    assert :sys.get_state(peer).ice.nominated_pair.local.type == "relay"

    :gen_udp.close(client)
    assert :ok = Peer.close(peer)
    assert_receive {:xgw, :closed, ^peer, :normal}
  end

  test "relay_only full mode completes ICE on USE-CANDIDATE" do
    mapped = {{203, 0, 113, 99}, 49_999}
    {turn_port, _pid, turn_sock} = TurnFixtures.start_echo_server(mapped: mapped)
    on_exit(fn -> :gen_udp.close(turn_sock) end)

    relay_line = Gather.build_relay(mapped) |> ICE.candidate_line()

    assert {:ok, listener} =
             Listener.start_link(
               ip: {127, 0, 0, 1},
               port: 0,
               turn_servers: ["turn:127.0.0.1:#{turn_port}"],
               relay_only: true
             )

    on_exit(fn -> if Process.alive?(listener), do: GenServer.stop(listener) end)
    Process.unlink(listener)
    port = Listener.port(listener)
    fp = Listener.local_fingerprint(listener)

    client_ufrag = "chromeUfrag"
    server_ufrag = "xgwufrag"
    server_pwd = "xgwpasswordxgwpasswordx"

    assert {:ok, peer} =
             Peer.start_supervised(handler: self(), listener: listener, ice_lite: false)

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

    assert hd(Peer.local_candidates(peer)).type == "relay"
    assert Peer.ice_phase(peer) == :gathering
    assert_receive {:xgw, :local_candidates_complete, ^peer}, 5_000

    {:ok, sock} = :gen_udp.open(0, [:binary, active: false])
    {:ok, local_port} = :inet.port(sock)

    assert :ok =
             Peer.add_remote_candidate(peer, %{
               candidate:
                 "candidate:2 1 UDP 1853824767 127.0.0.1 #{local_port} typ host",
               mid: "0"
             })

    assert :ok =
             Peer.add_remote_candidate(peer, %{end_of_candidates: true, mid: "0"})

    assert Peer.ice_phase(peer) == :checking

    req =
      StunFixtures.connectivity_check_wire(
        pwd: server_pwd,
        username: "#{server_ufrag}:#{client_ufrag}",
        use_candidate: true
      )

    assert :ok = :gen_udp.send(sock, {127, 0, 0, 1}, port, req)

    assert_receive {:xgw, :ice_connected, ^peer}, 2000
    assert Peer.ice_phase(peer) == :completed
    ice = :sys.get_state(peer).ice
    assert ice.nominated_pair.local.type == "relay"

    :gen_udp.close(sock)
    assert :ok = Peer.close(peer)
    assert_receive {:xgw, :closed, ^peer, :normal}
  end

  test "relay_only listener rejects answer without relay locals" do
    assert {:ok, listener} =
             Listener.start_link(
               ip: {127, 0, 0, 1},
               port: 0,
               turn_servers: ["turn:127.0.0.1:3478"],
               relay_only: true
             )

    on_exit(fn -> if Process.alive?(listener), do: GenServer.stop(listener) end)
    Process.unlink(listener)
    fp = Listener.local_fingerprint(listener)

    assert {:ok, peer} =
             Peer.start_supervised(handler: self(), listener: listener, ice_lite: false)

    assert {:error, :local_candidate_mismatch} =
             Peer.apply_descriptions(
               peer,
               SDPFixtures.chrome_offer(),
               SDPFixtures.xgw_full_answer(fp)
             )

    assert :ok = Peer.close(peer)
    assert_receive {:xgw, :closed, ^peer, :normal}
  end

end
