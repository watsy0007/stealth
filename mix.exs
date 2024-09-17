defmodule Stealth.MixProject do
  use Mix.Project

  @version "0.9.5"

  def project do
    [
      app: :stealth,
      version: @version,
      elixir: "~> 1.15",
      start_permanent: Mix.env() == :prod,
      build_embedded: Mix.env() == :prod,
      elixirc_paths: elixirc_paths(Mix.env()),
      aliases: aliases(),
      deps: deps(),
      description: "Stealth Server",
      releases: [
        stealth: [
          cookie: "Stealth",
          include_executables_for: [:unix]
        ]
      ]
    ]
  end

  # Run "mix help compile.app" to learn about applications.
  def application do
    [
      extra_applications: [:crypto, :logger],
      mod: {Stealth.Application, []}
    ]
  end

  defp aliases() do
    [
      release: "release --overwrite",
      test: "test --no-start"
    ]
  end

  defp elixirc_paths(:test), do: ["lib", "test/support"]
  defp elixirc_paths(_), do: ["lib", "web"]

  # Run "mix help deps" to learn about dependencies.
  defp deps do
    [
      {:cachex, "~> 3.6"}
    ]
  end
end
