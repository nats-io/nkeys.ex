defmodule Nkeys.MixProject do
  use Mix.Project

  def project do
    [
      app: :nkeys,
      version: "0.3.0",
      elixir: "~> 1.17",
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      description: "Support for nkey generation, parsing, and signing",
      package: [
        name: "nkeys",
        licenses: ["Apache-2"],
        links: %{
          "github" => "https://github.com/nats-io/nkeys.ex"
        }
      ]
    ]
  end

  # Run "mix help compile.app" to learn about applications.
  def application do
    [
      extra_applications: [:logger]
    ]
  end

  # Run "mix help deps" to learn about dependencies.
  defp deps do
    [
      {:ed25519, "~> 1.3"},
      {:kcl, "~> 1.4"},
      {:ex_doc, ">= 0.0.0", only: :dev, runtime: false}
    ]
  end
end
