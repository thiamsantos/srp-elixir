defmodule SRP.Server do
  @moduledoc """
  Server module.
  """

  @callback key_pair(binary()) :: KeyPair.t()
  @callback premaster_secret(binary(), KeyPair.t(), binary()) :: binary()
  @callback proof(binary(), binary(), binary()) :: binary()
  @callback valid_client_proof?(binary(), binary(), binary(), binary()) :: boolean()

  defmacro __using__(opts \\ []) do
    quote do
      @behaviour SRP.Server

      @impl true
      def key_pair(password_verifier), do: SRP.server_key_pair(password_verifier, unquote(opts))

      @impl true
      def premaster_secret(password_verifier, server, client_public_key) do
        SRP.server_premaster_secret(
          password_verifier,
          server,
          client_public_key,
          unquote(opts)
        )
      end

      @impl true
      def proof(client_proof, client_public_key, premaster_secret) do
        SRP.server_proof(client_proof, client_public_key, premaster_secret, unquote(opts))
      end

      @impl true
      def valid_client_proof?(
            client_proof,
            client_public_key,
            server_public_key,
            premaster_secret
          ) do
        SRP.valid_client_proof?(
          client_proof,
          client_public_key,
          server_public_key,
          premaster_secret,
          unquote(opts)
        )
      end
    end
  end
end
