defmodule XGW.PeerSetHandlerTest do
  use XGW.Test.Case

  alias XGW.Peer

  test "set_handler retargets notifications" do
    assert {:ok, peer} = Peer.start_supervised(handler: self(), ice_lite: true)
    assert {:ok, other} = start_handler()

    assert :ok = Peer.set_handler(peer, other)
    send(peer, {:xgw_internal, :dtls_fingerprint_mismatch})

    refute_receive {:xgw, :closed, ^peer, _}, 100
    assert_receive {:done, ^other, {:xgw, :closed, ^peer, :fingerprint_mismatch}}, 1000
  end

  defp start_handler do
    parent = self()

    pid =
      spawn(fn ->
        receive do
          msg -> send(parent, {:done, self(), msg})
        after
          2000 -> :ok
        end
      end)

    {:ok, pid}
  end
end
