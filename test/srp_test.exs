defmodule SRPTest do
  use ExUnit.Case, async: true
  use ExUnitProperties
  doctest SRP

  alias SRP.Group
  require SRP.Group

  describe "srp" do
    test "generate same premaster key on client and server" do
      identity = SRP.new_identity("alice", "password123")

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

  @tag :property
  describe "property tests" do
    property "srp" do
      check all username <- StreamData.string(:alphanumeric),
                password <- StreamData.string(:alphanumeric),
                hash_algorithm <-
                  StreamData.member_of([:sha224, :sha256, :sha384, :sha, :md5, :md4, :sha512]),
                prime_size <- StreamData.member_of(Group.valid_sizes()) do
        options = [hash_algorithm: hash_algorithm, prime_size: prime_size]
        identity = SRP.new_identity(username, password)

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
end
