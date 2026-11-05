defmodule XGW.PeerDcSendErrorTest do
  use ExUnit.Case, async: false

  alias XGW.Peer

  test "send_datachannel without sctp emits telemetry and handler error" do
    parent = self()

    handler =
      spawn(fn ->
        receive do
          msg -> send(parent, {:handler, msg})
        end
      end)

    handler_id = "dc-send-err-#{System.unique_integer([:positive])}"

    :ok =
      :telemetry.attach(
        handler_id,
        [:xgw, :peer, :dc_send_error],
        fn _e, m, meta, _c -> send(parent, {:telem, m, meta}) end,
        nil
      )

    on_exit(fn -> :telemetry.detach(handler_id) end)

    assert {:ok, peer} = Peer.start_link(handler: handler)
    assert {:error, :no_sctp} = Peer.send_datachannel(peer, make_ref(), "x")

    assert_receive {:telem, %{count: 1}, meta}
    assert meta.reason == :no_sctp
    assert_receive {:handler, {:xgw, :datachannel_send_error, ^peer, _ch, :no_sctp}}
    assert :ok = Peer.close(peer)
  end
end
