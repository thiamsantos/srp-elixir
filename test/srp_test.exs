defmodule SRPTest do
  use ExUnit.Case, async: true
  doctest SRP

  alias SRP.{Group, Identity}
  require SRP.Group

  describe "srp" do
    test "generate same premaster key on client and server" do
      identity = Identity.new("alice", "password123")

      register = SRP.generate_verifier(identity)
      server_key_pair = SRP.server_key_pair(register.password_verifier)
      client_key_pair = SRP.client_key_pair()

      client_proof =
        SRP.client_proof(
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

      assert SRP.valid_server_proof?(
               server_proof,
               identity,
               register.salt,
               client_key_pair,
               server_key_pair.public
             ) == true
    end
  end

  for prime_size <- Group.valid_sizes() do
    test "should work with prime of #{prime_size} bits" do
      identity = Identity.new("alice", "password123")

      options = [prime_size: unquote(prime_size)]
      register = SRP.generate_verifier(identity, options)
      server_key_pair = SRP.server_key_pair(register.password_verifier, options)
      client_key_pair = SRP.client_key_pair(options)

      client_proof =
        SRP.client_proof(
          identity,
          register.salt,
          client_key_pair,
          server_key_pair.public,
          options
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

  for hash_algorithm <- [:sha224, :sha256, :sha384, :sha, :md5, :md4, :sha512] do
    test "should work with hash #{hash_algorithm} " do
      identity = Identity.new("alice", "password123")

      options = [hash_algorithm: unquote(hash_algorithm)]
      register = SRP.generate_verifier(identity, options)
      server_key_pair = SRP.server_key_pair(register.password_verifier, options)
      client_key_pair = SRP.client_key_pair(options)

      client_proof =
        SRP.client_proof(
          identity,
          register.salt,
          client_key_pair,
          server_key_pair.public,
          options
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
