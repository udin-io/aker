defmodule ExLicence.MixProject do
  use Mix.Project

  @version "0.1.0-dev"
  @source_url "https://github.com/udin-io/ex_licence"

  def project do
    [
      app: :ex_licence,
      version: @version,
      elixir: "~> 1.18",
      start_permanent: Mix.env() == :prod,
      elixirc_paths: elixirc_paths(Mix.env()),
      deps: deps(),
      description: description(),
      package: package(),
      docs: docs(),
      name: "ExLicence",
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
    machine's TPM chip, signed activation requests, and licence files signed
    by a root key the app trusts.
    """
  end

  defp package do
    [
      licenses: ["Apache-2.0"],
      links: %{"GitHub" => @source_url},
      files: ~w(lib .formatter.exs mix.exs README.md LICENSE CHANGELOG.md),
      maintainers: ["Peter Shoukry"]
    ]
  end

  defp docs do
    [
      main: "readme",
      extras: ["README.md", "CHANGELOG.md", "LICENSE"],
      source_ref: "main"
    ]
  end
end
