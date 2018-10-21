defmodule SrpTest do
  use ExUnit.Case
  doctest Srp

  describe "gen_verifier/2" do
    test "should generate an verifier" do
      prime_size = 2048

      username = "thiago@example.com"
      password = "P@ssw0rd"

      register =
        Srp.generate_verifier(username, password, prime_size) |> IO.inspect(label: :register)

      server =
        Srp.server_key_pair(register.password_verifier, prime_size) |> IO.inspect(label: :server)

      client = Srp.client_key_pair(prime_size) |> IO.inspect(label: :client)

      client_premaster_secret =
        Srp.client_premaster_secret(
          prime_size,
          register.salt,
          username,
          password,
          client,
          server.public
        )
        |> IO.inspect(label: :client_premaster_secret)

      server_premaster_secret =
        Srp.server_premaster_secret(prime_size, client.public, server, register.password_verifier)
        |> IO.inspect(label: :server_premaster_secret)

      assert client_premaster_secret == server_premaster_secret
    end
  end
end
