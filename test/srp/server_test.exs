defmodule SRP.ServerTest do
  use ExUnit.Case, async: true

  alias SRP.Identity

  defmodule SRPServer do
    use SRP.Server
  end

  defmodule SRPServerWithOptions do
    use SRP.Server, prime_size: 8192, hash_algorithm: :sha512
  end

  describe "support srp client" do
    test "should generate premaster key" do
      identity = Identity.new("alice", "password123")

      register = SRP.generate_verifier(identity)
      client = SRP.client_key_pair()

      server = SRPServer.key_pair(register.password_verifier)

      client_premaster_secret =
        SRP.client_premaster_secret(
          identity,
          register.salt,
          client,
          server.public
        )

      server_premaster_secret =
        SRPServer.premaster_secret(register.password_verifier, server, client.public)

      assert client_premaster_secret == server_premaster_secret
    end
  end

  describe "support srp client with options" do
    test "should generate premaster key" do
      options = [prime_size: 8192, hash_algorithm: :sha512]
      identity = Identity.new("alice", "password123")

      register = SRP.generate_verifier(identity, options)
      client = SRP.client_key_pair(options)

      server = SRPServerWithOptions.key_pair(register.password_verifier)

      client_premaster_secret =
        SRP.client_premaster_secret(
          identity,
          register.salt,
          client,
          server.public,
          options
        )

      server_premaster_secret =
        SRPServerWithOptions.premaster_secret(register.password_verifier, server, client.public)

      assert client_premaster_secret == server_premaster_secret
    end
  end
end
