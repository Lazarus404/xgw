defmodule XGW.TrickleTest do
  use XGW.Test.Case

  alias XGW.{Listener, Peer}
  alias XGW.Test.SDPFixtures
  alias XMediaLib.Stun

  @moduletag :external

  test "trickle srflx after chrome offer reaches ice_connected" do
    assert {:ok, listener} = Listener.start_link(ip: {127, 0, 0, 1}, port: 0)
    on_exit(fn -> if Process.alive?(listener), do: GenServer.stop(listener) end)
    Process.unlink(listener)
    port = Listener.port(listener)
    fp = Listener.local_fingerprint(listener)

    client_ufrag = "chromeUfrag"
    server_ufrag = "xgwufrag"
    server_pwd = "xgwpasswordxgwpasswordx"

    assert {:ok, peer} =
             Peer.start_supervised(handler: self(), listener: listener, ice_lite: true)

    assert :ok =
             Peer.apply_descriptions(
               peer,
               SDPFixtures.chrome_offer(),
               SDPFixtures.xgw_answer(fp, ufrag: server_ufrag, pwd: server_pwd)
             )

    assert :ok =
             Peer.add_remote_candidate(peer, %{
               candidate: "candidate:2 1 UDP 1853824767 203.0.113.5 50000 typ srflx",
               mid: "0"
             })

    assert :ok =
             Peer.add_remote_candidate(peer, %{end_of_candidates: true, mid: "0"})

    {:ok, sock} = :gen_udp.open(0, [:binary, active: false])
    req = stun_check(server_pwd, "#{server_ufrag}:#{client_ufrag}")
    assert :ok = :gen_udp.send(sock, {127, 0, 0, 1}, port, req)
    assert_receive {:xgw, :ice_connected, ^peer}, 2000

    :gen_udp.close(sock)
    assert :ok = Peer.close(peer)
    assert_receive {:xgw, :closed, ^peer, :normal}
  end

  defp stun_check(pwd, username) do
    %Stun{
      class: :request,
      method: :binding,
      transactionid: 9_876_543_210,
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
