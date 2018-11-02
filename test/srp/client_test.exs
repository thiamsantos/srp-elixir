defmodule SRP.ClientTest do
  use ExUnit.Case, async: true

  alias SRP.Identity

  doctest SRP.Client

  defmodule SRPClient do
    use SRP.Client
  end

  defmodule SRPClientWithOptions do
    use SRP.Client, prime_size: 8192, hash_algorithm: :sha512
  end

  describe "support srp client" do
    test "should generate premaster key" do
      identity = Identity.new("alice", "password123")

      register = SRPClient.generate_verifier(identity)
      client_key_pair = SRPClient.key_pair()
      server_key_pair = SRP.server_key_pair(register.password_verifier)

      client_proof =
        SRPClient.proof(
          identity,
          register.salt,
          client_key_pair,
          server_key_pair.public
        )

      assert SRP.valid_client_proof?(
               client_proof,
               register.password_verifier,
               server_key_pair,
               client_key_pair.public
             ) == true

      server_proof =
        SRP.server_proof(
          client_proof,
          register.password_verifier,
          server_key_pair,
          client_key_pair.public
        )

      assert SRPClient.valid_server_proof?(
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
      register = SRPClientWithOptions.generate_verifier(identity)
      client_key_pair = SRPClientWithOptions.key_pair()
      server_key_pair = SRP.server_key_pair(register.password_verifier, options)

      client_proof =
        SRPClientWithOptions.proof(
          identity,
          register.salt,
          client_key_pair,
          server_key_pair.public
        )

      assert SRP.valid_client_proof?(
               client_proof,
               register.password_verifier,
               server_key_pair,
               client_key_pair.public,
               options
             ) == true

      server_proof =
        SRP.server_proof(
          client_proof,
          register.password_verifier,
          server_key_pair,
          client_key_pair.public,
          options
        )

      assert SRPClientWithOptions.valid_server_proof?(
               server_proof,
               identity,
               register.salt,
               client_key_pair,
               server_key_pair.public
             ) == true
    end
  end
end
