defmodule SRP.Client do
  @moduledoc """
  Client module.
  """
  @callback generate_verifier(Identity.t()) :: Verifier.t()
  @callback key_pair :: KeyPair.t()
  @callback proof(binary(), binary(), KeyPair.t(), binary()) :: binary()
  @callback valid_server_proof?(binary(), Identity.t(), binary(), KeyPair.t(), binary()) :: boolean()

  defmacro __using__(opts) do
    quote do
      @behaviour SRP.Client

      @impl true
      def key_pair, do: SRP.client_key_pair(unquote(opts))

      @impl true
      def generate_verifier(identity) do
        SRP.generate_verifier(identity, unquote(opts))
      end

      @impl true
      def proof(
            identity,
            salt,
            client_key_pair,
            server_public_key
          ) do
        SRP.client_proof(identity, salt, client_key_pair, server_public_key, unquote(opts))
      end

      @impl true
      def valid_server_proof?(
            server_proof,
            identity,
            salt,
            client_key_pair,
            server_public_key
          ) do
        SRP.valid_server_proof?(
          server_proof,
          identity,
          salt,
          client_key_pair,
          server_public_key,
          unquote(opts)
        )
      end
    end
  end
end
