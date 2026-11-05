defmodule XGW.TurnIntegrationTest do
  use XGW.Test.Case

  alias XGW.{Listener, Peer, TURN.Client}
  alias XGW.Test.{SDPFixtures, TurnFixtures}

  @tag :external
  test "relay allocation is deleted on peer close" do
    mapped = {{203, 0, 113, 88}, 40_001}
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

    assert {:ok, peer} =
             Peer.start_supervised(handler: self(), listener: listener, ice_lite: false)

    fp = Listener.local_fingerprint(listener)

    assert :ok =
             Peer.apply_descriptions(
               peer,
               SDPFixtures.chrome_offer(),
               SDPFixtures.xgw_full_answer(fp,
                 host_candidate: Listener.host_candidate_line(listener)
               )
             )

    assert_receive {:xgw, :local_candidate, ^peer, %{candidate: line}}, 5_000
    assert line =~ "typ relay"

    assert :ok = Peer.close(peer)
    assert_peer_closed(peer, :normal)

    timeout = Listener.gather_timeout_ms(listener)

    send_recv = fn wire, {ip, port} ->
      Listener.turn_request(listener, ip, port, timeout, wire)
    end

    fake = %{
      turn_server: {{127, 0, 0, 1}, turn_port},
      relay: mapped,
      lifetime_s: 600,
      username: "",
      realm: "",
      nonce: "",
      integrity_key: <<>>
    }

    assert :ok = Client.delete(send_recv, fake)
  end
end
