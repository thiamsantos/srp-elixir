defmodule SRP.ClientTest do
  use ExUnit.Case, async: true

  defmodule SRPClient do
    use SRP.Client
  end

  defmodule SRPClientWithOptions do
    use SRP.Client, prime_size: 8192, hash_algorithm: :sha512
  end

  describe "support srp client" do
    test "should generate premaster key" do
      username = "alice"
      password = "password123"

      register = SRPClient.generate_verifier(username, password)
      client = SRPClient.key_pair()

      server = SRP.server_key_pair(register.password_verifier)

      client_premaster_secret =
        SRPClient.premaster_secret(
          register.salt,
          username,
          password,
          client,
          server.public
        )

      server_premaster_secret =
        SRP.server_premaster_secret(register.password_verifier, server, client.public)

      assert client_premaster_secret == server_premaster_secret
    end
  end

  describe "support srp client with options" do
    test "should generate premaster key" do
      options = [prime_size: 8192, hash_algorithm: :sha512]
      username = "alice"
      password = "password123"

      register = SRPClientWithOptions.generate_verifier(username, password)
      client = SRPClientWithOptions.key_pair()

      server = SRP.server_key_pair(register.password_verifier, options)

      client_premaster_secret =
        SRPClientWithOptions.premaster_secret(
          register.salt,
          username,
          password,
          client,
          server.public
        )

      server_premaster_secret =
        SRP.server_premaster_secret(register.password_verifier, server, client.public, options)

      assert client_premaster_secret == server_premaster_secret
    end
  end
end
