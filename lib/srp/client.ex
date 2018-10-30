defmodule SRP.Client do
  @moduledoc """
  Client module.
  """
  @callback generate_verifier(Identity.t()) :: Verifier.t()
  @callback key_pair :: KeyPair.t()
  @callback premaster_secret(Identity.t(), binary(), KeyPair.t(), binary()) :: binary()
  @callback proof(binary(), binary(), binary()) :: binary()
  @callback valid_server_proof?(binary(), binary(), binary(), binary()) :: boolean()

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
      def premaster_secret(identity, salt, client, server_public_key) do
        SRP.client_premaster_secret(
          identity,
          salt,
          client,
          server_public_key,
          unquote(opts)
        )
      end

      @impl true
      def proof(client_public_key, server_public_key, premaster_secret) do
        SRP.client_proof(client_public_key, server_public_key, premaster_secret, unquote(opts))
      end

      @impl true
      def valid_server_proof?(
            server_proof,
            client_public_key,
            server_public_key,
            premaster_secret
          ) do
        SRP.valid_server_proof?(
          server_proof,
          client_public_key,
          server_public_key,
          premaster_secret,
          unquote(opts)
        )
      end
    end
  end
end
