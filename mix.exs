defmodule Aker.MixProject do
  use Mix.Project

  @version "0.1.0"
  @source_url "https://github.com/udin-io/aker"

  def project do
    [
      app: :aker,
      version: @version,
      elixir: "~> 1.18",
      start_permanent: Mix.env() == :prod,
      elixirc_paths: elixirc_paths(Mix.env()),
      deps: deps(),
      description: description(),
      package: package(),
      docs: docs(),
      name: "Aker",
      source_url: @source_url
    ]
  end

  def application do
    [
      extra_applications: [:logger, :crypto]
    ]
  end

  defp elixirc_paths(:test), do: ["lib", "test/support"]
  defp elixirc_paths(_), do: ["lib"]

  defp deps do
    [
      {:plug, "~> 1.0", only: [:test]},
      {:nimble_options, "~> 1.0"},
      {:req, "~> 0.5"},
      {:ex_doc, "~> 0.40", only: [:dev]},
      {:mix_audit, "~> 2.0", only: [:dev, :test]},
      {:sobelow, "~> 0.18", only: [:dev, :test]},
      {:credo, "~> 1.0", only: [:dev, :test]},
      {:jason, "~> 1.0"},
      {:igniter, "~> 0.6", only: [:dev, :test]}
    ]
  end

  defp description do
    """
    Licences for on-premises Elixir apps: an install key in a file or the
    machine's TPM chip, signed activation requests, licence files signed by a
    root key the app trusts, and a gate that checks the licence at boot and
    every hour and renews it.
    """
  end

  defp package do
    [
      licenses: ["Apache-2.0"],
      links: %{"GitHub" => @source_url},
      files: ~w(lib guides .formatter.exs mix.exs README.md LICENSE CHANGELOG.md),
      maintainers: ["Peter Shoukry"]
    ]
  end

  defp docs do
    [
      main: "readme",
      extras: [
        "README.md",
        "guides/getting_started.md",
        "guides/licence_format.md",
        "CHANGELOG.md",
        "LICENSE"
      ],
      groups_for_extras: [Guides: ~r{guides/.+\.md}],
      source_ref: "v#{@version}"
    ]
  end
end
