defmodule SRP.Server do
  @moduledoc """
  Defines a SRP server.

  ```elixir
  defmodule MyApp.SRP.Server do
    use SRP.Server
  end
  ```

  It accepts a `prime_size` and a `hash_algorithm` as options.

  ```elixir
  defmodule MyApp.SRP.ClientWithOptions do
    use SRP.Server, prime_size: 8192, hash_algorithm: :sha512
  end
  ```
  """

  @doc """
  See more information at `SRP.server_key_pair/2`.
  """
  @callback key_pair(binary()) :: KeyPair.t()

  @doc """
  See more information at `SRP.server_proof/5`.
  """
  @callback proof(binary(), binary(), KeyPair.t(), binary()) :: binary()

  @doc """
  See more information at `SRP.valid_client_proof?/5`.
  """
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
