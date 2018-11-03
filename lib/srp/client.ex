defmodule SRP.Client do
  @moduledoc """
  Defines a SRP client.

  ```elixir
  defmodule MyApp.SRP.Client do
    use SRP.Client
  end
  ```

  It accepts a `prime_size` and a `hash_algorithm` as options.

  ```elixir
  defmodule MyApp.SRP.ClientWithOptions do
    use SRP.Client, prime_size: 8192, hash_algorithm: :sha512
  end
  ```
  """

  @doc """
  See more information at `SRP.generate_verifier/2`.
  """
  @callback generate_verifier(Identity.t()) :: IdentityVerifier.t()

  @doc """
  See more information at `SRP.client_key_pair/1`.
  """
  @callback key_pair :: KeyPair.t()

  @doc """
  See more information at `SRP.client_proof/5`.
  """
  @callback proof(binary(), binary(), KeyPair.t(), binary()) :: binary()

  @doc """
  See more information at `SRP.valid_server_proof?/6`.
  """
  @callback valid_server_proof?(binary(), Identity.t(), binary(), KeyPair.t(), binary()) ::
              boolean()

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
