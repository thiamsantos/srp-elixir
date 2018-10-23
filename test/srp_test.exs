defmodule SRPTest do
  use ExUnit.Case
  doctest SRP

  alias SRP.Group
  require SRP.Group

  describe "srp" do
    test "generate same premaster key on client and server" do
      prime_size = 1024

      username = "alice"
      password = "password123"

      register = SRP.generate_verifier(prime_size, username, password)
      server = SRP.server_key_pair(prime_size, register.password_verifier)
      client = SRP.client_key_pair(prime_size)

      client_premaster_secret =
        SRP.client_premaster_secret(
          prime_size,
          register.salt,
          username,
          password,
          client,
          server.public
        )

      server_premaster_secret =
        SRP.server_premaster_secret(prime_size, register.password_verifier, server, client.public)

      assert client_premaster_secret == server_premaster_secret
    end
  end

  for prime_size <- Group.valid_sizes() do
    test "should work with prime of #{prime_size} bits" do
      username = "alice"
      password = "password123"

      register = SRP.generate_verifier(unquote(prime_size), username, password)
      server = SRP.server_key_pair(unquote(prime_size), register.password_verifier)
      client = SRP.client_key_pair(unquote(prime_size))

      client_premaster_secret =
        SRP.client_premaster_secret(
          unquote(prime_size),
          register.salt,
          username,
          password,
          client,
          server.public
        )

      server_premaster_secret =
        SRP.server_premaster_secret(
          unquote(prime_size),
          register.password_verifier,
          server,
          client.public
        )

      assert client_premaster_secret == server_premaster_secret
    end
  end
end
