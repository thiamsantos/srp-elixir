defmodule SRPTest do
  use ExUnit.Case, async: true
  doctest SRP

  alias SRP.{Group, Identity}
  require SRP.Group

  describe "srp" do
    test "generate same premaster key on client and server" do
      identity = Identity.new("alice", "password123")

      register = SRP.generate_verifier(identity)
      server = SRP.server_key_pair(register.password_verifier)
      client = SRP.client_key_pair()

      client_premaster_secret =
        SRP.client_premaster_secret(
          identity,
          register.salt,
          client,
          server.public
        )

      server_premaster_secret =
        SRP.server_premaster_secret(register.password_verifier, server, client.public)

      assert client_premaster_secret == server_premaster_secret

      client_proof = SRP.client_proof(client.public, server.public, client_premaster_secret)

      assert SRP.valid_client_proof?(
               client_proof,
               client.public,
               server.public,
               server_premaster_secret
             ) == true

      server_proof = SRP.server_proof(client_proof, client.public, server_premaster_secret)

      assert SRP.valid_server_proof?(
               server_proof,
               client.public,
               server.public,
               server_premaster_secret
             ) == true
    end
  end

  for prime_size <- Group.valid_sizes() do
    test "should work with prime of #{prime_size} bits" do
      identity = Identity.new("alice", "password123")

      register = SRP.generate_verifier(identity, prime_size: unquote(prime_size))
      server = SRP.server_key_pair(register.password_verifier, prime_size: unquote(prime_size))
      client = SRP.client_key_pair(prime_size: unquote(prime_size))

      client_premaster_secret =
        SRP.client_premaster_secret(
          identity,
          register.salt,
          client,
          server.public,
          prime_size: unquote(prime_size)
        )

      server_premaster_secret =
        SRP.server_premaster_secret(
          register.password_verifier,
          server,
          client.public,
          prime_size: unquote(prime_size)
        )

      assert client_premaster_secret == server_premaster_secret
    end
  end

  for hash_algorithm <- [:sha224, :sha256, :sha384, :sha, :md5, :md4, :sha512] do
    test "should work with hash #{hash_algorithm} " do
      identity = Identity.new("alice", "password123")

      register = SRP.generate_verifier(identity, hash_algorithm: unquote(hash_algorithm))

      server =
        SRP.server_key_pair(register.password_verifier, hash_algorithm: unquote(hash_algorithm))

      client = SRP.client_key_pair(hash_algorithm: unquote(hash_algorithm))

      client_premaster_secret =
        SRP.client_premaster_secret(
          identity,
          register.salt,
          client,
          server.public,
          hash_algorithm: unquote(hash_algorithm)
        )

      server_premaster_secret =
        SRP.server_premaster_secret(
          register.password_verifier,
          server,
          client.public,
          hash_algorithm: unquote(hash_algorithm)
        )

      assert client_premaster_secret == server_premaster_secret

      client_proof =
        SRP.client_proof(
          client.public,
          server.public,
          client_premaster_secret,
          hash_algorithm: unquote(hash_algorithm)
        )

      assert SRP.valid_client_proof?(
               client_proof,
               client.public,
               server.public,
               server_premaster_secret,
               hash_algorithm: unquote(hash_algorithm)
             ) == true

      server_proof =
        SRP.server_proof(
          client_proof,
          client.public,
          server_premaster_secret,
          hash_algorithm: unquote(hash_algorithm)
        )

      assert SRP.valid_server_proof?(
               server_proof,
               client.public,
               server.public,
               server_premaster_secret,
               hash_algorithm: unquote(hash_algorithm)
             ) == true
    end
  end
end
