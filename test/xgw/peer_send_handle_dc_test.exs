defmodule XGW.PeerSendHandleDcTest do
  use ExUnit.Case, async: false

  alias XGW.Peer
  alias XGW.Peer.SendHandle

  defmodule Sink do
    @moduledoc false
    def hot_send_dc(collector, ref, data, type \\ :string) do
      send(collector, {:dc_hot, ref, data, type})
      :ok
    end
  end

  defmodule AsyncPeer do
    @moduledoc false
    use GenServer

    def start_link, do: GenServer.start_link(__MODULE__, self())
    def drain(pid), do: GenServer.call(pid, :drain)

    @impl true
    def init(parent), do: {:ok, %{parent: parent, events: []}}

    @impl true
    def handle_call({:send_datachannel, ref, data}, _from, state) do
      handle_call({:send_datachannel, ref, data, :string}, nil, state)
    end

    def handle_call({:send_datachannel, ref, data, type}, _from, state) do
      {:reply, :ok, %{state | events: [{:call, ref, data, type} | state.events]}}
    end

    def handle_call(:drain, _from, state) do
      {:reply, Enum.reverse(state.events), %{state | events: []}}
    end

    @impl true
    def handle_cast({:send_datachannel, ref, data}, state) do
      handle_cast({:send_datachannel, ref, data, :string}, state)
    end

    def handle_cast({:send_datachannel, ref, data, type}, state) do
      send(state.parent, {:async_dc, ref, data, type})
      {:noreply, %{state | events: [{:cast, ref, data, type} | state.events]}}
    end
  end

  setup do
    SendHandle.ensure_table!()
    peer = self()
    on_exit(fn -> SendHandle.invalidate(peer) end)
    %{peer: peer}
  end

  test "dc passthrough invokes MFA without GenServer", %{peer: peer} do
    ref = make_ref()
    assert :ok = SendHandle.publish_dc_passthrough(peer, {Sink, :hot_send_dc, self()})
    assert :ok = SendHandle.send_datachannel(peer, ref, "hello")
    assert_receive {:dc_hot, ^ref, "hello", :string}
  end

  test "dc passthrough MFA receives binary PPI type", %{peer: peer} do
    ref = make_ref()
    assert :ok = SendHandle.publish_dc_passthrough(peer, {Sink, :hot_send_dc, self()})
    assert :ok = SendHandle.send_datachannel(peer, ref, <<0x82>>, :binary)
    assert_receive {:dc_hot, ^ref, <<0x82>>, :binary}
  end

  test "missing dc row returns not_ready", %{peer: peer} do
    assert {:error, :not_ready} = SendHandle.send_datachannel(peer, make_ref(), "x")
  end

  test "rtp passthrough row is use_genserver for dc send", %{peer: peer} do
    assert :ok = SendHandle.publish_passthrough(peer, {Sink, :hot_send_dc, self()})
    assert {:error, :use_genserver} = SendHandle.send_datachannel(peer, make_ref(), "x")
  end

  test "send_datachannel_async delivers via GenServer.cast" do
    assert {:ok, peer} = AsyncPeer.start_link()
    ref = make_ref()
    assert :ok = Peer.send_datachannel_async(peer, ref, "async-hi")
    assert_receive {:async_dc, ^ref, "async-hi", :string}, 200
    assert [{:cast, ^ref, "async-hi", :string}] = AsyncPeer.drain(peer)
    GenServer.stop(peer)
  end

  test "send_datachannel_async passes binary PPI type" do
    assert {:ok, peer} = AsyncPeer.start_link()
    ref = make_ref()
    assert :ok = Peer.send_datachannel_async(peer, ref, <<0x82>>, :binary)
    assert_receive {:async_dc, ^ref, <<0x82>>, :binary}, 200
    assert [{:cast, ^ref, <<0x82>>, :binary}] = AsyncPeer.drain(peer)
    GenServer.stop(peer)
  end
end
