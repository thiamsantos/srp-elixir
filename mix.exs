defmodule Srp.MixProject do
  use Mix.Project

  def project do
    [
      app: :srp,
      version: "0.1.1",
      elixir: "~> 1.6",
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      test_coverage: [tool: ExCoveralls],
      preferred_cli_env: [coveralls: :test, "coveralls.travis": :test, "coveralls.html": :test],
      name: "SRP",
      source_url: "https://github.com/thiamsantos/srp-elixir",
      docs: docs(),
      package: package(),
      description: "Implementation of the Secure Remote Password Protocol"
    ]
  end

  def application do
    [
      extra_applications: [:crypto]
    ]
  end

  defp docs do
    [
      main: "SRP"
    ]
  end

  defp package do
    [
      name: "srp",
      licenses: ["Apache 2.0"],
      links: %{"GitHub" => "https://github.com/thiamsantos/srp-elixir"}
    ]
  end

  defp deps do
    [
      {:credo, "~> 0.10.0", only: [:dev, :test], runtime: false},
      {:excoveralls, "~> 0.10.1", only: :test, runtime: false},
      {:ex_doc, "~> 0.18.0", only: :dev, runtime: false},
      {:stream_data, "~> 0.4.2", only: :test}
    ]
  end
end
