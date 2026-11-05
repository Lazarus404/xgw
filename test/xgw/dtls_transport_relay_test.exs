defmodule XGW.DTLS.TransportRelayTest do
  use ExUnit.Case, async: true

  alias XGW.DTLS.Transport
  alias XGW.TURN.Client
  alias XMediaLib.Stun

  test "send wraps payload in TURN Send Indication when relay_send is set" do
    {:ok, sock} = :gen_udp.open(0, [:binary, active: false, ip: {127, 0, 0, 1}])
    on_exit(fn -> :gen_udp.close(sock) end)

    {:ok, turn_sock} = :gen_udp.open(0, [:binary, active: false, ip: {127, 0, 0, 1}])
    on_exit(fn -> :gen_udp.close(turn_sock) end)
    {:ok, turn_port} = :inet.port(turn_sock)

    peer = {{203, 0, 113, 50}, 40_000}

    alloc = %{
      relay: {{203, 0, 113, 99}, 49_999},
      turn_server: {{127, 0, 0, 1}, turn_port},
      lifetime_s: 600,
      username: "",
      nonce: "",
      realm: "",
      integrity_key: <<>>
    }

    :persistent_term.put({Transport, sock}, %{listener: self(), owner: nil, pending: []})
    on_exit(fn -> :persistent_term.erase({Transport, sock}) end)

    assert :ok = Transport.set_relay_send(sock, alloc, peer)
    assert :ok = Transport.send(sock, {1, 2, 3, 4}, 9, <<"dtls-flight">>)

    assert {:ok, {_ip, _port, wire}} = :gen_udp.recv(turn_sock, 0, 1_000)
    assert {:ok, %Stun{class: :indication, method: :send, attrs: attrs}} = Stun.decode(wire)
    assert attrs.xor_peer_address == peer
    assert attrs.data == <<"dtls-flight">>

    assert :ok = Transport.clear_relay_send(sock)
    assert :ok = Transport.send(sock, {127, 0, 0, 1}, turn_port, <<"plain">>)
    assert {:ok, {_, _, <<"plain">>}} = :gen_udp.recv(turn_sock, 0, 1_000)
  end

  test "send wraps payload in ChannelData when channel is armed" do
    {:ok, sock} = :gen_udp.open(0, [:binary, active: false, ip: {127, 0, 0, 1}])
    on_exit(fn -> :gen_udp.close(sock) end)

    {:ok, turn_sock} = :gen_udp.open(0, [:binary, active: false, ip: {127, 0, 0, 1}])
    on_exit(fn -> :gen_udp.close(turn_sock) end)
    {:ok, turn_port} = :inet.port(turn_sock)

    peer = {{203, 0, 113, 51}, 40_001}
    channel = 0x4000

    alloc = %{
      relay: {{203, 0, 113, 99}, 49_999},
      turn_server: {{127, 0, 0, 1}, turn_port},
      lifetime_s: 600,
      username: "",
      nonce: "",
      realm: "",
      integrity_key: <<>>
    }

    :persistent_term.put({Transport, sock}, %{listener: self(), owner: nil, pending: []})
    on_exit(fn -> :persistent_term.erase({Transport, sock}) end)

    assert :ok = Transport.set_relay_send(sock, alloc, peer, channel: channel)
    assert :ok = Transport.send(sock, {1, 2, 3, 4}, 9, <<"dtls-flight">>)

    assert {:ok, {_ip, _port, wire}} = :gen_udp.recv(turn_sock, 0, 1_000)
    assert {:ok, ^channel, <<"dtls-flight">>} = Client.decode_channel_data(wire)
  end

  test "send frames DTLS over ICE-TCP when tcp_send is set" do
    {:ok, sock} = :gen_udp.open(0, [:binary, active: false, ip: {127, 0, 0, 1}])
    on_exit(fn -> :gen_udp.close(sock) end)

    {:ok, listen} = :gen_tcp.listen(0, [:binary, active: false, ip: {127, 0, 0, 1}, reuseaddr: true])
    on_exit(fn -> :gen_tcp.close(listen) end)
    {:ok, tcp_port} = :inet.port(listen)

    peer = {{127, 0, 0, 1}, tcp_port}

    parent = self()

    {:ok, acceptor} =
      Task.start_link(fn ->
        {:ok, server} = :gen_tcp.accept(listen)
        {:ok, <<len::16, rest::binary>>} = :gen_tcp.recv(server, 0, 1_000)
        need = len - byte_size(rest)
        {:ok, more} = if need > 0, do: :gen_tcp.recv(server, need, 1_000), else: {:ok, <<>>}
        send(parent, {:framed, rest <> more})
        :gen_tcp.close(server)
      end)

    on_exit(fn -> if Process.alive?(acceptor), do: Process.exit(acceptor, :kill) end)

    {:ok, client} = :gen_tcp.connect({127, 0, 0, 1}, tcp_port, [:binary, active: false])
    on_exit(fn -> :gen_tcp.close(client) end)

    :persistent_term.put({Transport, sock}, %{listener: self(), owner: nil, pending: []})
    on_exit(fn -> :persistent_term.erase({Transport, sock}) end)

    assert :ok = Transport.set_tcp_send(sock, client, peer)
    assert :ok = Transport.send(sock, elem(peer, 0), elem(peer, 1), <<"dtls-flight">>)

    assert_receive {:framed, <<"dtls-flight">>}, 1_000
  end
end
