defmodule XGW.TestHandler do
  @moduledoc false
  use Agent

  def start_link(_opts \\ []), do: Agent.start_link(fn -> [] end, name: __MODULE__)

  def reset, do: Agent.update(__MODULE__, fn _ -> [] end)

  def messages, do: Agent.get(__MODULE__, &Enum.reverse/1)

  def push(msg), do: Agent.update(__MODULE__, fn msgs -> [msg | msgs] end)

  def await(kind, timeout \\ 1000) do
    deadline = System.monotonic_time(:millisecond) + timeout

    receive do
      msg = {:xgw, ^kind, _, _} ->
        push(msg)
        msg
    after
      timeout ->
        wait_until(deadline, kind)
    end
  end

  defp wait_until(deadline, kind) do
    remaining = deadline - System.monotonic_time(:millisecond)

    if remaining <= 0 do
      raise "no {:xgw, #{inspect(kind)}, ...} within timeout"
    else
      await(kind, remaining)
    end
  end
end
