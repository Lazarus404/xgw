defmodule XGW.Stun.TCPTest do
  use ExUnit.Case, async: true
  doctest XGW.Stun.TCP

  alias XGW.Stun.TCP
  alias XMediaLib.Stun

  test "frame and recv round-trip" do
    wire =
      %Stun{
        class: :request,
        method: :binding,
        transactionid: 42,
        fingerprint: true,
        attrs: %{}
      }
      |> Stun.encode()

    {:ok, server} = :gen_tcp.listen(0, [:binary, active: false, ip: {127, 0, 0, 1}])
    {:ok, port} = :inet.port(server)
    parent = self()

    Task.start(fn ->
      {:ok, client} = :gen_tcp.accept(server, 1_000)
      assert {:ok, got} = TCP.recv(client, 1_000)
      assert got == wire
      :gen_tcp.close(client)
      :gen_tcp.close(server)
      send(parent, :done)
    end)

    {:ok, sock} = :gen_tcp.connect(~c"127.0.0.1", port, [:binary, active: false], 1_000)
    assert :ok = TCP.send(sock, wire)
    :gen_tcp.close(sock)
    assert_receive :done, 2_000
  end
end
