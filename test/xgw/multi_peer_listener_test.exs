defmodule XGW.MultiPeerListenerTest do
  use XGW.Test.Case

  alias XGW.Listener
  alias XMediaLib.Stun

  defmodule PacketForwarder do
    use GenServer

    def start_link(parent), do: GenServer.start_link(__MODULE__, parent)

    def init(parent), do: {:ok, parent}

    def handle_cast({:packet, kind, data, meta}, parent) do
      send(parent, {:packet, self(), kind, data, meta})
      {:noreply, parent}
    end
  end

  # Peer.deliver/4 expects a Peer GenServer; forwarder mimics via Listener calling Peer.deliver.
  # Tests use Listener APIs + a thin fake that implements deliver by wrapping GenServer.

  defp start_forwarder do
    parent = self()
    {:ok, pid} = PacketForwarder.start_link(parent)
    on_exit(fn -> if Process.alive?(pid), do: GenServer.stop(pid) end)
    pid
  end

  test "bind_ufrag routes STUN Binding to the matching peer only" do
    assert {:ok, listener} = Listener.start_link(ip: {127, 0, 0, 1}, port: 0)
    on_exit(fn -> if Process.alive?(listener), do: GenServer.stop(listener) end)
    Process.unlink(listener)
    port = Listener.port(listener)

    a = start_forwarder()
    b = start_forwarder()
    assert :ok = Listener.register_peer(listener, a)
    assert :ok = Listener.register_peer(listener, b)
    assert :ok = Listener.bind_ufrag(listener, a, "ufragA")
    assert :ok = Listener.bind_ufrag(listener, b, "ufragB")

    {:ok, sock} = :gen_udp.open(0, [:binary, active: false])
    on_exit(fn -> :gen_udp.close(sock) end)

    req_a = stun_binding("pwd", "ufragA:cliA")
    assert :ok = :gen_udp.send(sock, {127, 0, 0, 1}, port, req_a)
    assert_receive {:packet, ^a, :stun, ^req_a, %{from: _}}, 1000
    refute_receive {:packet, ^b, _, _, _}, 100

    req_b = stun_binding("pwd", "ufragB:cliB")
    assert :ok = :gen_udp.send(sock, {127, 0, 0, 1}, port, req_b)
    assert_receive {:packet, ^b, :stun, ^req_b, %{from: _}}, 1000
    refute_receive {:packet, ^a, _, _, _}, 100
  end

  test "bind_remote routes RTP-classified bytes to bound peer" do
    assert {:ok, listener} = Listener.start_link(ip: {127, 0, 0, 1}, port: 0)
    on_exit(fn -> if Process.alive?(listener), do: GenServer.stop(listener) end)
    Process.unlink(listener)
    port = Listener.port(listener)

    a = start_forwarder()
    b = start_forwarder()
    assert :ok = Listener.register_peer(listener, a)
    assert :ok = Listener.register_peer(listener, b)

    {:ok, sock} = :gen_udp.open(0, [:binary, active: false])
    on_exit(fn -> :gen_udp.close(sock) end)
    {:ok, client_port} = :inet.port(sock)
    from = {{127, 0, 0, 1}, client_port}

    assert :ok = Listener.bind_remote(listener, a, from)

    # RTP-like first byte (128-191)
    rtp = <<128, 111, 0, 1, 0, 0, 0, 2, 0, 0, 3, 233, 0, 0, 0, 0>>
    assert :ok = :gen_udp.send(sock, {127, 0, 0, 1}, port, rtp)
    assert_receive {:packet, ^a, :rtp, ^rtp, %{from: ^from}}, 1000
    refute_receive {:packet, ^b, _, _, _}, 100
  end

  test "unregister clears route keys" do
    assert {:ok, listener} = Listener.start_link(ip: {127, 0, 0, 1}, port: 0)
    on_exit(fn -> if Process.alive?(listener), do: GenServer.stop(listener) end)
    Process.unlink(listener)
    port = Listener.port(listener)

    a = start_forwarder()
    assert :ok = Listener.register_peer(listener, a)
    assert :ok = Listener.bind_ufrag(listener, a, "ufragA")
    assert :ok = Listener.unregister_peer(listener, a)

    {:ok, sock} = :gen_udp.open(0, [:binary, active: false])
    on_exit(fn -> :gen_udp.close(sock) end)
    req = stun_binding("pwd", "ufragA:cli")
    assert :ok = :gen_udp.send(sock, {127, 0, 0, 1}, port, req)
    refute_receive {:packet, _, _, _, _}, 200
  end

  test "single registered peer receives packets without bind_ufrag" do
    assert {:ok, listener} = Listener.start_link(ip: {127, 0, 0, 1}, port: 0)
    on_exit(fn -> if Process.alive?(listener), do: GenServer.stop(listener) end)
    Process.unlink(listener)
    port = Listener.port(listener)

    a = start_forwarder()
    assert :ok = Listener.register_peer(listener, a)

    {:ok, sock} = :gen_udp.open(0, [:binary, active: false])
    on_exit(fn -> :gen_udp.close(sock) end)
    req = stun_binding("pwd", "any:cli")
    assert :ok = :gen_udp.send(sock, {127, 0, 0, 1}, port, req)
    assert_receive {:packet, ^a, :stun, ^req, _}, 1000
  end

  test "allocate_turn_channel yields distinct channels per peer" do
    assert {:ok, listener} = Listener.start_link(ip: {127, 0, 0, 1}, port: 0)
    on_exit(fn -> if Process.alive?(listener), do: GenServer.stop(listener) end)
    Process.unlink(listener)

    a = start_forwarder()
    b = start_forwarder()
    assert :ok = Listener.register_peer(listener, a)
    assert :ok = Listener.register_peer(listener, b)

    assert {:ok, ch_a} = Listener.allocate_turn_channel(listener, a)
    assert {:ok, ch_b} = Listener.allocate_turn_channel(listener, b)
    assert ch_a != ch_b
    assert ch_a >= 0x4000
    assert ch_b >= 0x4000

    assert :ok = Listener.bind_turn_channel(listener, a, ch_a)
    assert :ok = Listener.bind_turn_channel(listener, b, ch_b)

    port = Listener.port(listener)
    {:ok, sock} = :gen_udp.open(0, [:binary, active: false])
    on_exit(fn -> :gen_udp.close(sock) end)

    frame_a = XGW.TURN.Client.encode_channel_data(ch_a, <<"inner-a">>)
    assert :ok = :gen_udp.send(sock, {127, 0, 0, 1}, port, frame_a)
    assert_receive {:packet, ^a, :turn_channel, ^frame_a, _}, 1000
    refute_receive {:packet, ^b, _, _, _}, 100
  end

  defp stun_binding(pwd, username) do
    Stun.encode(%Stun{
      class: :request,
      method: :binding,
      fingerprint: true,
      integrity: true,
      transactionid: 1_234_567_890,
      key: pwd,
      attrs: %{
        username: username,
        priority: <<0, 0, 0, 1>>,
        ice_controlling: <<1, 2, 3, 4, 5, 6, 7, 8>>
      }
    })
  end
end
