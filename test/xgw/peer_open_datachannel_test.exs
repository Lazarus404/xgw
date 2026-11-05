defmodule XGW.PeerOpenDatachannelTest do
  use ExUnit.Case, async: false

  alias XGW.Peer
  alias XSockets.Sctp.Association, as: SctpAssociation

  setup do
    if SctpAssociation.available?() do
      :ok
    else
      {:skip, "ex_sctp NIF not loaded"}
    end
  end

  test "open_datachannel returns not_connected without SCTP" do
    assert {:ok, peer} = Peer.start_link(handler: self())
    assert {:error, :not_connected} = Peer.open_datachannel(peer, "chat")
    assert :ok = Peer.close(peer)
  end

  test "open_datachannel synthesizes handler datachannel event" do
    assert {:ok, peer} = Peer.start_link(handler: self())

    active = connect_assoc!()

    :sys.replace_state(peer, fn state ->
      %{state | sctp: active, phase: :media}
    end)

    assert {:ok, info} = Peer.open_datachannel(peer, "rpc")
    assert info.label == "rpc"
    assert is_reference(info.ref)
    assert is_integer(info.id)

    assert_receive {:xgw, :datachannel, ^peer, ^info}
    assert :ok = Peer.close(peer)
  end

  test "open_datachannel passes reliability opts" do
    assert {:ok, peer} = Peer.start_link(handler: self())
    active = connect_assoc!()

    :sys.replace_state(peer, fn state ->
      %{state | sctp: active, phase: :media}
    end)

    assert {:ok, info} =
             Peer.open_datachannel(peer, "state",
               ordered: false,
               reliability: :rexmit,
               param: 0
             )

    assert info.label == "state"
    assert_receive {:xgw, :datachannel, ^peer, got}
    assert got.ref == info.ref
    assert :ok = Peer.close(peer)
  end

  defp connect_assoc! do
    active = SctpAssociation.new(role: :active)
    passive = SctpAssociation.new(role: :passive)
    {events, active} = SctpAssociation.connect(active)
    {active, passive, _} = pipe(active, passive, events)

    {active, _passive, _} =
      tick_until(active, passive, fn a, p ->
        a.state == :connected and p.state == :connected
      end)

    assert active.state == :connected
    active
  end

  defp pipe(from, to, events) do
    Enum.reduce(events, {from, to, []}, fn
      {:transmit, packets}, {a, b, acc} ->
        Enum.reduce(packets, {a, b, acc}, fn pkt, {aa, bb, acc2} ->
          {evs, bb2} = SctpAssociation.handle_packet(bb, pkt)
          {bb3, aa2, nested} = pipe(bb2, aa, evs)
          {aa2, bb3, acc2 ++ evs ++ nested}
        end)

      {:timeout, ms}, {a, b, acc} when is_integer(ms) and ms > 0 ->
        Process.sleep(min(ms, 3))
        {evs, a2} = SctpAssociation.handle_timeout(a)
        {a3, b2, nested} = pipe(a2, b, evs)
        {a3, b2, acc ++ nested}

      ev, {a, b, acc} ->
        {a, b, acc ++ [ev]}
    end)
  end

  defp tick_until(a, b, done?, seed_events \\ []) do
    Enum.reduce_while(1..80, {a, b, seed_events}, fn _, {aa, bb, acc} ->
      if done?.(aa, bb) do
        {:halt, {aa, bb, acc}}
      else
        {evs, aa} = SctpAssociation.handle_timeout(aa)
        {aa, bb, nested} = pipe(aa, bb, evs)
        {evs, bb} = SctpAssociation.handle_timeout(bb)
        {bb, aa, nested2} = pipe(bb, aa, evs)
        Process.sleep(2)
        {:cont, {aa, bb, acc ++ nested ++ nested2}}
      end
    end)
  end
end
