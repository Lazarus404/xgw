defmodule XGW.Test.Case do
  @moduledoc false

  use ExUnit.CaseTemplate

  using do
    quote do
      use ExUnit.Case, async: false

      alias XGW.Test.Helpers

      import XGW.Test.Helpers

      setup do
        lock_task = Helpers.lock_integration!()

        on_exit(fn ->
          Helpers.unlock_integration!(lock_task)
        end)

        :ok
      end
    end
  end
end
