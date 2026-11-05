defmodule XGW.ICETCPTest do
  use XGW.Test.Case

  alias XGW.{ICE, ICE.Gather, Listener}

  @tag :external
  test "passive TCP candidate line and listen accepts connections" do
    assert {:ok, listener} =
             Listener.start_link(
               ip: {127, 0, 0, 1},
               port: 0,
               ice_tcp_enabled: true
             )

    on_exit(fn ->
      if Process.alive?(listener) do
        try do
          GenServer.stop(listener)
        catch
          :exit, _ -> :ok
        end
      end
    end)
    Process.unlink(listener)

    [tcp_line | _] = Listener.tcp_candidate_lines(listener)
    assert tcp_line =~ " typ host "
    assert tcp_line =~ " tcptype passive"

    tcp_port = Listener.tcp_port(listener)
    assert is_integer(tcp_port)

    assert {:ok, sock} = :gen_tcp.connect(~c"127.0.0.1", tcp_port, [:binary, active: false], 2_000)
    :gen_tcp.close(sock)
  end

  test "gather tcp_passive_candidates uses tcp transport" do
    cands = Gather.tcp_passive_candidates({{127, 0, 0, 1}, 9_000}, include_loopback: true)
    assert cands != []
    assert Enum.all?(cands, &(&1.transport == "tcp"))
    assert Enum.all?(cands, &(&1.rest == "tcptype passive"))
    assert hd(cands) |> ICE.candidate_line() =~ "TCP"
  end

  test "tcp_candidate_lines omit UDP host candidates" do
    assert {:ok, listener} =
             Listener.start_link(
               ip: {127, 0, 0, 1},
               port: 0,
               ice_tcp_enabled: true,
               include_loopback: true
             )

    on_exit(fn ->
      if Process.alive?(listener) do
        try do
          GenServer.stop(listener)
        catch
          :exit, _ -> :ok
        end
      end
    end)

    Process.unlink(listener)

    tcp_lines = Listener.tcp_candidate_lines(listener)
    assert tcp_lines != []
    assert Enum.all?(tcp_lines, &(&1 =~ " TCP "))
    refute Enum.any?(tcp_lines, &(&1 =~ " UDP "))
  end
end
