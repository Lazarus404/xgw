defmodule XGW.PeerDcIsolationTest do
  use ExUnit.Case, async: false

  alias XGW.Peer
  alias XGW.Peer.Datachannel

  test "Peer GenServer stays responsive while Datachannel egress is queued" do
    assert {:ok, peer} = Peer.start_link(handler: self())

    assert {:ok, dc} =
             Datachannel.start_link(
               peer: peer,
               handler: self(),
               ssl_sock: nil,
               role: :passive,
               send_dtls: fn _st, _pkt -> :ok end
             )

    :sys.replace_state(peer, fn state ->
      %{state | datachannel: dc, phase: :media}
    end)

    :sys.suspend(dc)
    ref = make_ref()

    Enum.each(1..40, fn i ->
      Peer.send_datachannel_async(peer, ref, "x#{i}", :string)
    end)

    {usec, _state} =
      :timer.tc(fn ->
        :sys.get_state(peer)
      end)

    assert usec < 50_000,
           "Peer get_state took #{usec}us; DC casts must not enter the Peer mailbox"

    :sys.resume(dc)
    :ok = Peer.close(peer)
  end
end
