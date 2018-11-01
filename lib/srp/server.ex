defmodule SRP.Server do
  @moduledoc """
  Server module.
  """

  @callback key_pair(binary()) :: KeyPair.t()
  @callback proof(binary(), binary(), KeyPair.t(), binary()) :: binary()
  @callback valid_client_proof?(binary(), binary(), KeyPair.t(), binary()) :: boolean()

  defmacro __using__(opts \\ []) do
    quote do
      @behaviour SRP.Server

      @impl true
      def key_pair(password_verifier), do: SRP.server_key_pair(password_verifier, unquote(opts))

      @impl true
      def proof(
            client_proof,
            password_verifier,
            server_key_pair,
            client_public_key
          ) do
        SRP.server_proof(
          client_proof,
          password_verifier,
          server_key_pair,
          client_public_key,
          unquote(opts)
        )
      end

      @impl true
      def valid_client_proof?(
            client_proof,
            password_verifier,
            server_key_pair,
            client_public_key
          ) do
        SRP.valid_client_proof?(
          client_proof,
          password_verifier,
          server_key_pair,
          client_public_key,
          unquote(opts)
        )
      end
    end
  end
end
