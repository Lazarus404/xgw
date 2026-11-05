defmodule XGW.MixProject do
  use Mix.Project

  def project do
    [
      app: :xgw,
      version: "0.1.0",
      elixir: "~> 1.15",
      start_permanent: Mix.env() == :prod,
      elixirc_paths: elixirc_paths(Mix.env()),
      erlc_paths: ["src"],
      erlc_options: erlc_options(),
      deps: deps(),
      description: "WebRTC ICE/DTLS/SRTP gateway for XTurn.",
      source_url: "https://github.com/Lazarus404/xgw",
      docs: [
        extras: ["README.md"],
        main: "readme"
      ],
      package: package()
    ]
  end

  # Compile the XGW-patched OTP dtls_packet_demux against ssl headers.
  defp erlc_options do
    ssl_dir = ssl_lib_dir()

    [
      :debug_info,
      {:i, Path.join(ssl_dir, "src")},
      {:i, Path.join(ssl_dir, "include")}
    ]
  end

  defp ssl_lib_dir do
    case :code.lib_dir(:ssl) do
      dir when is_list(dir) ->
        List.to_string(dir)

      {:error, _} ->
        # Nested Mix.Project loads (path deps) can run before OTP lib dirs resolve.
        {out, 0} =
          System.cmd("erl", [
            "-noshell",
            "-eval",
            "io:format(\"~s\", [code:lib_dir(ssl)]), halt()."
          ])

        out
    end
  end

  def application do
    [
      extra_applications: [:logger, :ssl],
      mod: {XGW.Application, []}
    ]
  end

  defp elixirc_paths(env) do
    paths = ["lib"]
    paths = if env == :test, do: paths ++ ["test/support"], else: paths

    # Spike needs Plug/Bandit. Opt-in via XGW_SPIKE=1, or when this package is the
    # Mix root under :dev/:test (not when compiled as another app's dependency).
    if spike_compile?(env), do: paths ++ ["spike"], else: paths
  end

  defp spike_compile?(env) do
    System.get_env("XGW_SPIKE") == "1" or
      (env in [:dev, :test] and mix_project_root?())
  end

  defp mix_project_root? do
    case Mix.Project.config()[:build_path] do
      nil ->
        true

      path ->
        String.starts_with?(Path.expand(path), Path.expand(__DIR__))
    end
  end

  defp deps do
    [
      {:xmedialib, "~> 0.3.0"},
      {:xsockets, "~> 1.0.0"},
      {:ex_sctp, "~> 0.1"},
      {:bandit, "~> 1.6", only: [:dev, :test]},
      {:plug, "~> 1.16", only: [:dev, :test]},
      {:ex_doc, "~> 0.31", only: :dev, runtime: false}
    ]
  end

  defp package do
    [
      licenses: ["Apache-2.0"],
      links: %{"GitHub" => "https://github.com/Lazarus404/xgw"}
    ]
  end
end
