defmodule Srp.MixProject do
  use Mix.Project

  def project do
    [
      app: :srp,
      version: "0.1.0",
      elixir: "~> 1.6",
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      test_coverage: [tool: ExCoveralls],
      preferred_cli_env: [coveralls: :test, "coveralls.travis": :test, "coveralls.html": :test],
      name: "SRP",
      source_url: "https://github.com/thiamsantos/srp-elixir"
    ]
  end

  # Run "mix help compile.app" to learn about applications.
  def application do
    [
      extra_applications: [:crypto]
    ]
  end

  # Run "mix help deps" to learn about dependencies.
  defp deps do
    [
      {:credo, "~> 0.10.0", only: [:dev, :test], runtime: false},
      {:excoveralls, "~> 0.10.1", only: :test, runtime: false},
      {:ex_doc, "~> 0.18.0", only: :dev, runtime: false},
      {:stream_data, "~> 0.4.2", only: :test}
    ]
  end
end
