defmodule XGW.ListenerCandidateTest do
  use XGW.Test.Case

  alias XGW.Listener

  @tag :external
  test "host_candidate_line reflects bound socket" do
    assert {:ok, listener} = Listener.start_link(ip: {127, 0, 0, 1}, port: 0)
    on_exit(fn -> if Process.alive?(listener), do: GenServer.stop(listener) end)
    Process.unlink(listener)

    port = Listener.port(listener)
    line = Listener.host_candidate_line(listener)

    assert line =~ "typ host"
    assert line =~ Integer.to_string(port)
    assert line =~ "candidate:"

    c = Listener.host_candidate(listener)
    assert c.type == "host"
    assert c.port == port
    assert c.foundation != "xgw"
    assert c.ip =~ "."
  end

  @tag :external
  test "host_candidate_lines returns multiple entries for advertised_ips" do
    assert {:ok, listener} =
             Listener.start_link(
               ip: {127, 0, 0, 1},
               port: 0,
               advertised_ips: [{127, 0, 0, 1}, {192, 0, 2, 1}],
               include_loopback: false
             )

    on_exit(fn -> if Process.alive?(listener), do: GenServer.stop(listener) end)
    Process.unlink(listener)

    lines = Listener.host_candidate_lines(listener)
    assert length(lines) == 2
    assert Enum.all?(lines, &String.contains?(&1, "typ host"))
  end
end
