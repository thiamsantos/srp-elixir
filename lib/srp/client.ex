defmodule SRP.Client do
  @moduledoc """
  Client module.
  """
  @callback generate_verifier(Identity.t()) :: Verifier.t()
  @callback key_pair :: KeyPair.t()
  @callback premaster_secret(Identity.t(), binary(), KeyPair.t(), binary()) :: binary()

  defmacro __using__(opts) do
    quote do
      @behaviour SRP.Client

      def key_pair, do: SRP.client_key_pair(unquote(opts))

      def generate_verifier(identity) do
        SRP.generate_verifier(identity, unquote(opts))
      end

      def premaster_secret(identity, salt, client, server_public_key) do
        SRP.client_premaster_secret(
          identity,
          salt,
          client,
          server_public_key,
          unquote(opts)
        )
      end
    end
  end
end
