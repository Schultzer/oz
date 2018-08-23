defmodule Oz.MixProject do
  use Mix.Project

  @version "0.1.0"
  def project do
    [
      app: :oz,
      version: @version,
      elixir: "~> 1.6",
      start_permanent: Mix.env() == :prod,
      deps: deps()
    ]
  end

  def application do
    [
      extra_applications: [:logger]
    ]
  end

  defp deps do
    [
      {:iron, github: "Schultzer/iron"},
      {:hawk, github: "Schultzer/hawk"},
      {:deep, github: "Schultzer/deep"},
      {:plug, "~> 1.4.5", optional: true},
      {:bypass, "~> 0.8.1", only: :test}
    ]
  end
end
