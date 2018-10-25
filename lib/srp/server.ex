defmodule SRP.Server do
  @callback key_pair(binary()) :: KeyPair.t()
  @callback premaster_secret(binary(), KeyPair.t(), binary()) :: binary()

  defmacro __using__(opts) do
    quote do
      @behaviour SRP.Server

      def key_pair(password_verifier), do: SRP.server_key_pair(password_verifier, unquote(opts))

      def premaster_secret(password_verifier, server, client_public_key) do
        SRP.server_premaster_secret(
          password_verifier,
          server,
          client_public_key,
          unquote(opts)
        )
      end
    end
  end
end
