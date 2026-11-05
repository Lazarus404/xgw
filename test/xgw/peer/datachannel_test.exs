defmodule XGW.Peer.DatachannelTest do
  use ExUnit.Case, async: false

  alias XGW.Peer.Datachannel
  alias XSockets.Sctp.Association, as: SctpAssociation

  setup do
    if Code.ensure_loaded?(SctpAssociation) and SctpAssociation.available?() do
      :ok
    else
      {:skip, "ex_sctp NIF not loaded"}
    end
  end

  test "start_link publishes ETS so Peer.send path can resolve the child" do
    peer = self()
    assert :error = Datachannel.lookup(peer)

    assert {:ok, dc} =
             Datachannel.start_link(
               peer: peer,
               handler: self(),
               ssl_sock: nil,
               role: :passive
             )

    assert {:ok, ^dc} = Datachannel.lookup(peer)
    assert Process.alive?(dc)

    :ok = GenServer.stop(dc)
    assert :error = Datachannel.lookup(peer)
  end

  test "handler callbacks use peer pid, not datachannel pid" do
    peer = spawn(fn -> Process.sleep(60_000) end)
    on_exit(fn -> Process.exit(peer, :kill) end)

    {assoc, channel_ref} = open_local_channel!()

    assert {:ok, dc} =
             Datachannel.start_link(
               peer: peer,
               handler: self(),
               ssl_sock: nil,
               assoc: assoc,
               send_dtls: fn _st, _pkt -> :ok end
             )

    assert {:ok, _info} = Datachannel.open_datachannel(dc, "chat")

    # Server-open synthesizes a handler event with the Peer identity.
    assert_receive {:xgw, :datachannel, ^peer, info}
    assert info.label == "chat"
    assert is_reference(info.ref)

    assert :ok = Datachannel.send_datachannel_async(dc, channel_ref, "ping", :string)
    # May or may not emit messages depending on channel readiness; identity is the contract.
    refute_receive {:xgw, :datachannel, ^dc, _}, 50
    refute_receive {:xgw, :datachannel_message, ^dc, _, _}, 50

    :ok = GenServer.stop(dc)
  end

  test "cast drain batches multiple pending sends into one telemetry sample" do
    parent = self()
    handler_id = "dc-batch-#{System.unique_integer([:positive])}"

    :ok =
      :telemetry.attach(
        handler_id,
        [:xgw, :peer, :dc_batch],
        fn _e, %{size: size}, _meta, _c -> send(parent, {:batch, size}) end,
        nil
      )

    on_exit(fn -> :telemetry.detach(handler_id) end)

    assert {:ok, dc} =
             Datachannel.start_link(
               peer: self(),
               handler: self(),
               ssl_sock: nil,
               role: :passive,
               send_dtls: fn _st, _pkt -> :ok end
             )

    :sys.suspend(dc)
    ref = make_ref()

    for i <- 1..20 do
      :ok = Datachannel.send_datachannel_async(dc, ref, "m#{i}", :string)
    end

    :sys.resume(dc)

    assert_receive {:batch, size} when size >= 2, 1_000
    :ok = GenServer.stop(dc)
  end

  test "ssl_closed clears association and unpublishes" do
    assert {:ok, dc} =
             Datachannel.start_link(
               peer: self(),
               handler: self(),
               ssl_sock: :fake_sock,
               role: :passive,
               send_dtls: fn _st, _pkt -> :ok end
             )

    assert {:ok, ^dc} = Datachannel.lookup(self())
    send(dc, {:ssl_closed, :fake_sock})
    assert_receive {:xgw_internal, :datachannel_down, ^dc, :ssl_closed}, 1_000

    Enum.reduce_while(1..50, nil, fn _, _ ->
      if Process.alive?(dc), do: (Process.sleep(10); {:cont, nil}), else: {:halt, :dead}
    end)

    refute Process.alive?(dc)
    assert :error = Datachannel.lookup(self())
  end

  defp open_local_channel! do
    active = SctpAssociation.new(role: :active)
    passive = SctpAssociation.new(role: :passive)
    {events, active} = SctpAssociation.connect(active)
    {active, passive, _} = pipe(active, passive, events)

    {active, _passive, _} =
      tick_until(active, passive, fn a, p ->
        a.state == :connected and p.state == :connected
      end)

    {events, ref, active} = SctpAssociation.open_channel(active, "pre")
    {active, passive, _} = pipe(active, passive, events)

    {active, _passive, _} =
      tick_until(active, passive, fn a, p ->
        local_open?(a) and remote_open?(p)
      end)

    assert local_open?(active)
    {active, ref}
  end

  defp local_open?(assoc),
    do: Enum.any?(assoc.channels, fn {_r, ch} -> ch.ready_state == :open end)

  defp remote_open?(assoc),
    do: Enum.any?(assoc.channels, fn {_r, ch} -> ch.ready_state == :open end)

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
        {aa, bb, nested2} = pipe(bb, aa, evs)
        {:cont, {aa, bb, acc ++ nested ++ nested2}}
      end
    end)
  end
end
