defmodule XGW.PeerTurnUnwrapTest do
  use XGW.Test.Case

  alias XGW.{Listener, Peer, TURN.Client}
  alias XGW.Test.{SDPFixtures, StunFixtures}
  alias XMediaLib.Stun

  test "inbound TURN Data Indication Binding reaches ICE and replies via Send Indication" do
    mapped = {{203, 0, 113, 77}, 41_001}
    {turn_port, _pid, turn_sock} = XGW.Test.TurnFixtures.start_echo_server(mapped: mapped)
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

    data_ind =
      Stun.encode(%Stun{
        class: :indication,
        method: 7,
        fingerprint: false,
        transactionid: 42,
        attrs: %{
          xor_peer_address: {{127, 0, 0, 1}, client_port},
          data: binding
        }
      })

    # Arrive as if from the TURN server.
    Peer.deliver(peer, :stun, data_ind, %{from: {{127, 0, 0, 1}, turn_port}})

    assert_receive {:xgw, :ice_connected, ^peer}, 2_000

    st = :sys.get_state(peer)
    assert Map.get(st.peer_channels, {{127, 0, 0, 1}, client_port}) == 0x4000
    assert Map.get(st.turn_channels, 0x4000) == {{127, 0, 0, 1}, client_port}

    assert :ok = Peer.close(peer)
    assert_receive {:xgw, :closed, ^peer, :normal}
  end

  test "inbound ChannelData Binding unwraps to ICE when channel is bound" do
    mapped = {{203, 0, 113, 78}, 41_011}
    {turn_port, _pid, turn_sock} = XGW.Test.TurnFixtures.start_echo_server(mapped: mapped)
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
    peer_ep = {{127, 0, 0, 1}, client_port}
    channel = 0x4000

    assert :ok =
             Peer.add_remote_candidate(peer, %{
               candidate: "candidate:2 1 UDP 1853824767 127.0.0.1 #{client_port} typ host",
               mid: "0"
             })

    assert :ok = Peer.add_remote_candidate(peer, %{end_of_candidates: true, mid: "0"})

    :sys.replace_state(peer, fn st ->
      %{
        st
        | turn_channels: %{channel => peer_ep},
          peer_channels: %{peer_ep => channel},
          next_turn_channel: channel + 1
      }
    end)

    binding =
      StunFixtures.connectivity_check_wire(
        pwd: server_pwd,
        username: "#{server_ufrag}:#{client_ufrag}",
        use_candidate: true
      )

    channel_data = Client.encode_channel_data(channel, binding)
    Peer.deliver(peer, :turn_channel, channel_data, %{from: {{127, 0, 0, 1}, turn_port}})

    assert_receive {:xgw, :ice_connected, ^peer}, 2_000
    assert :ok = Peer.close(peer)
  end

  test "inbound ChannelData with unknown channel is ignored" do
    mapped = {{203, 0, 113, 79}, 41_012}
    {turn_port, _pid, turn_sock} = XGW.Test.TurnFixtures.start_echo_server(mapped: mapped)
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

    channel_data = Client.encode_channel_data(0x4001, binding)
    Peer.deliver(peer, :turn_channel, channel_data, %{from: {{127, 0, 0, 1}, turn_port}})

    refute_receive {:xgw, :ice_connected, ^peer}, 500
    assert :sys.get_state(peer).phase == :ice_wait
    assert :ok = Peer.close(peer)
  end
end
