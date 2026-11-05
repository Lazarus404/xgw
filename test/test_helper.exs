{:ok, _} = Application.ensure_all_started(:xgw)
exclude = if System.get_env("XTURN_LIVE") == "1", do: [], else: [:external]
ExUnit.start(exclude: exclude)
