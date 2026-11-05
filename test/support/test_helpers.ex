defmodule XGW.Test.Helpers do
  @moduledoc false

  import ExUnit.Assertions, only: [flunk: 1]

  @lock {:xgw, :integration_test}

  @doc false
  def ensure_started!(retries \\ 5) do
    {:ok, _} = Application.ensure_all_started(:xgw)

    case Process.whereis(XGW.PeerSupervisor) do
      pid when is_pid(pid) ->
        if Process.alive?(pid) do
          :ok
        else
          retry_ensure!(retries)
        end

      _ ->
        retry_ensure!(retries)
    end
  end

  @doc false
  def lock_integration!(timeout \\ 30_000) do
    holder = self()

    task =
      Task.async(fn ->
        :global.trans(@lock, fn ->
          send(holder, :xgw_integration_lock)

          receive do
            :xgw_integration_unlock -> :ok
          end
        end, [node()], timeout)
      end)

    Process.unlink(task.pid)

    receive do
      :xgw_integration_lock ->
        ensure_started!()
        task
    after
      timeout -> raise "integration lock timeout after #{timeout}ms"
    end
  end

  @doc false
  def unlock_integration!(%Task{} = task) do
    ref = Process.monitor(task.pid)
    send(task.pid, :xgw_integration_unlock)

    receive do
      {:DOWN, ^ref, :process, _pid, _reason} -> :ok
    after
      5_000 -> Process.demonitor(ref, [:flush])
    end
  end

  defp retry_ensure!(0), do: raise "XGW.PeerSupervisor unavailable after ensure_all_started"

  defp retry_ensure!(retries) do
    Process.sleep(20)
    ensure_started!(retries - 1)
  end

  @doc false
  def assert_peer_closed(peer, reason \\ :normal, timeout \\ 500) when is_pid(peer) do
    receive do
      {:xgw, :local_candidates_complete, ^peer} ->
        assert_peer_closed(peer, reason, timeout)

      {:xgw, :local_candidate, ^peer, _} ->
        assert_peer_closed(peer, reason, timeout)

      {:xgw, :closed, ^peer, ^reason} ->
        :ok

      {:xgw, :closed, ^peer, other} ->
        flunk("expected close reason #{inspect(reason)}, got #{inspect(other)}")
    after
      timeout ->
        flunk(
          "expected {:xgw, :closed, #{inspect(peer)}, #{inspect(reason)}} within #{timeout}ms"
        )
    end
  end
end
