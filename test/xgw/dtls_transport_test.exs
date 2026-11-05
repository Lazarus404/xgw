defmodule XGW.DTLS.TransportTest do
  use ExUnit.Case, async: false

  alias XGW.DTLS.Transport

  test "ignore_owner prevents Peer from stealing DTLS inject destination" do
    sock = make_ref()
    ssl_owner = self()
    peer = spawn(fn -> receive do: (:stop -> :ok) end)

    :persistent_term.put({Transport, sock}, %{listener: self(), owner: nil, pending: []})

    assert :ok = Transport.controlling_process(sock, ssl_owner)
    assert :ok = Transport.ignore_owner(peer)
    assert :ok = Transport.controlling_process(sock, peer)
    assert %{owner: ^ssl_owner} = :persistent_term.get({Transport, sock})

    assert :ok = Transport.inject(sock, {127, 0, 0, 1}, 9, "dtls")
    assert_receive {:udp, ^sock, {127, 0, 0, 1}, 9, "dtls"}

    send(peer, :stop)
  end

  test "non-ignored owner updates replace previous owner" do
    sock = make_ref()
    first = self()
    second = spawn(fn -> receive do: (:stop -> :ok) end)

    :persistent_term.put({Transport, sock}, %{listener: self(), owner: nil, pending: []})
    assert :ok = Transport.controlling_process(sock, first)
    assert :ok = Transport.controlling_process(sock, second)
    assert %{owner: ^second, demux: ^first} = :persistent_term.get({Transport, sock})

    send(second, :stop)
  end

  test "set_inject_owner routes injects per remote" do
    sock = make_ref()
    demux = spawn(fn -> receive do: (:stop -> :ok) end)
    parent = self()

    owner_a =
      spawn(fn ->
        receive do
          {:udp, ^sock, _, _, data} -> send(parent, {:got, :a, data})
        end

        receive do: (:stop -> :ok)
      end)

    owner_b =
      spawn(fn ->
        receive do
          {:udp, ^sock, _, _, data} -> send(parent, {:got, :b, data})
        end

        receive do: (:stop -> :ok)
      end)

    remote_a = {{203, 0, 113, 1}, 40_000}
    remote_b = {{203, 0, 113, 2}, 40_001}

    :persistent_term.put({Transport, sock}, %{listener: self(), owner: demux, pending: []})
    on_exit(fn -> :persistent_term.erase({Transport, sock}) end)

    assert :ok = Transport.set_inject_owner(sock, remote_a, owner_a)
    assert :ok = Transport.set_inject_owner(sock, remote_b, owner_b)

    assert :ok = Transport.inject(sock, elem(remote_a, 0), elem(remote_a, 1), "a")
    assert :ok = Transport.inject(sock, elem(remote_b, 0), elem(remote_b, 1), "b")

    assert_receive {:got, :a, "a"}, 500
    assert_receive {:got, :b, "b"}, 500

    send(owner_a, :stop)
    send(owner_b, :stop)
    send(demux, :stop)
  end

  test "peername resolves relay remote via inject owner mapping" do
    sock = make_ref()
    owner = self()
    peer = {{203, 0, 113, 9}, 50_000}

    alloc = %{
      relay: {{203, 0, 113, 99}, 49_999},
      turn_server: {{127, 0, 0, 1}, 9},
      lifetime_s: 600,
      username: "",
      nonce: "",
      realm: "",
      integrity_key: <<>>
    }

    :persistent_term.put({Transport, sock}, %{listener: self(), owner: owner, pending: []})
    on_exit(fn -> :persistent_term.erase({Transport, sock}) end)

    assert :ok = Transport.set_inject_owner(sock, peer, owner)
    assert :ok = Transport.set_relay_send(sock, alloc, peer)
    assert {:ok, ^peer} = Transport.peername(sock)
  end
end
