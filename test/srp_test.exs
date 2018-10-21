defmodule SRPTest do
  use ExUnit.Case
  doctest SRP

  require SRP.Group

  describe "gen_verifier/2" do
    test "should generate an verifier" do
      prime_size = 8192

      username = "thiago@example.com"
      password = "P@ssw0rd"

      register =
        SRP.generate_verifier(prime_size, username, password) |> IO.inspect(label: :register)

      server =
        SRP.server_key_pair(prime_size, register.password_verifier) |> IO.inspect(label: :server)

      client = SRP.client_key_pair(prime_size) |> IO.inspect(label: :client)

      client_premaster_secret =
        SRP.client_premaster_secret(
          prime_size,
          register.salt,
          username,
          password,
          client,
          server.public
        )
        |> IO.inspect(label: :client_premaster_secret)

      server_premaster_secret =
        SRP.server_premaster_secret(prime_size, register.password_verifier, server, client.public)
        |> IO.inspect(label: :server_premaster_secret)

      assert client_premaster_secret == server_premaster_secret
    end
  end
end
