defmodule SRP.ServerTest do
  use ExUnit.Case, async: true

  alias SRP.Identity

  doctest SRP.Server

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
      client_key_pair = SRP.client_key_pair()
      server_key_pair = SRPServer.key_pair(register.password_verifier)

      client_proof =
        SRP.client_proof(
          identity,
          register.salt,
          client_key_pair,
          server_key_pair.public
        )

      assert SRPServer.valid_client_proof?(
               client_proof,
               register.password_verifier,
               server_key_pair,
               client_key_pair.public
             ) == true

      server_proof =
        SRPServer.proof(
          client_proof,
          register.password_verifier,
          server_key_pair,
          client_key_pair.public
        )

      assert SRP.valid_server_proof?(
               server_proof,
               identity,
               register.salt,
               client_key_pair,
               server_key_pair.public
             ) == true
    end
  end

  describe "support srp client with options" do
    test "should generate premaster key" do
      options = [prime_size: 8192, hash_algorithm: :sha512]
      identity = Identity.new("alice", "password123")

      register = SRP.generate_verifier(identity, options)
      client_key_pair = SRP.client_key_pair(options)
      server_key_pair = SRPServerWithOptions.key_pair(register.password_verifier)

      client_proof =
        SRP.client_proof(
          identity,
          register.salt,
          client_key_pair,
          server_key_pair.public,
          options
        )

      assert SRPServerWithOptions.valid_client_proof?(
               client_proof,
               register.password_verifier,
               server_key_pair,
               client_key_pair.public
             ) == true

      server_proof =
        SRPServerWithOptions.proof(
          client_proof,
          register.password_verifier,
          server_key_pair,
          client_key_pair.public
        )

      assert SRP.valid_server_proof?(
               server_proof,
               identity,
               register.salt,
               client_key_pair,
               server_key_pair.public,
               options
             ) == true
    end
  end
end
