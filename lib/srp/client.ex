defmodule SRP.Client do
  @moduledoc """
  Client module.
  """
  @callback generate_verifier(String.t(), String.t()) :: Verifier.t()
  @callback key_pair :: KeyPair.t()
  @callback premaster_secret(binary(), String.t(), String.t(), KeyPair.t(), binary()) :: binary()

  defmacro __using__(opts) do
    quote do
      @behaviour SRP.Client

      def key_pair, do: SRP.client_key_pair(unquote(opts))

      def generate_verifier(username, password) do
        SRP.generate_verifier(username, password, unquote(opts))
      end

      def premaster_secret(salt, username, password, client, server_public_key) do
        SRP.client_premaster_secret(
          salt,
          username,
          password,
          client,
          server_public_key,
          unquote(opts)
        )
      end
    end
  end
end
