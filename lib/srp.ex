defmodule SRP do
  @moduledoc """
  SRP provides an implementation of the Secure Remote Password Protocol presented on
  [The SRP Authentication and Key Exchange System](https://tools.ietf.org/html/rfc2945),
  [Using the Secure Remote Password (SRP) Protocol for TLS Authentication](https://tools.ietf.org/html/rfc5054)
  and [The Secure Remote Password Protocol](http://srp.stanford.edu/ndss.html).

  The protocol provides a way to do zero-knowledge authentication between client and servers.
  By using the SRP protocol you can:
  - authenticate without ever sending a password over the network.
  - authenticate without the risk of anyone learning any of your secrets – even
    if they intercept your communication.
  - authenticate both the identity of the client and the server to guarantee
    that a client isn’t communicating with an impostor server.

  ## Signing up

  After the user provides his username and password, the client must generate
  a password verifier. Then it must send to the server:

  - The username for future identification.
  - The password verifier that will be used in the future to verify the client credentials.
  - The salt used in the process.

  ```elixir
  username = "alice"
  password = "password123"

  identity = SRP.new_identity(username, password)
  %SRP.IdentityVerifier{username: username, salt: salt, password_verifier: password_verifier} =
    SRP.generate_verifier(identity)

  # Send to the server -> username + salt + password_verifier
  # Server stores the information
  ```

  ## Logging in

  Authenticating a user on the server involves multiple steps.

  1. The client sends to the server the username.
  2. The server finds the password verifier and salt for that username.
  Then it generates a ephemeral key pair and sends back to the client the salt and the public key.

  ```elixir
  # Find the record for the given username
  # Load from the database the password_verifier, and the salt
  key_pair = SRP.server_key_pair(password_verifier)

  # Send back to the client -> key_pair.public + salt
  ```

  If the username does not exist the server can send a fake value.
  It is important to not reveal if an username is registered on the system or not.
  An attacker could use the login to find the registered usernames
  and try a dictionary attack specific for those users.

  3. The client generates a key pair and a client proof of identity.
  Then the client sends to the server the proof and the client's public key.

  ```elixir
  # receives from the server the server_public_key and the salt.

  identity = SRP.new_identity(username, password)
  key_pair = SRP.client_key_pair()
  proof = SRP.client_proof(identity, salt, key_pair, server_public_key)

  # Send to the server -> proof + server_public_key
  ```

  4. Server verify client proof then build its own proof of identity.
  Then sends back the server's proof.

  ```elixir
  valid? = SRP.valid_client_proof?(client_proof, password_verifier, server_key_pair, client_public_key)

  if valid? do
    # Send back to client the server's proof -> server_proof
  else
    # Send back unauthorized
  end
  ```

  5. The client receives the server's proof and validates it.
  This step can be skipped if you don't feel the need to verify the server's identity.

  ```elixir
  identity = SRP.new_identity(username, password)
  valid? = SRP.valid_server_proof?(server_proof, identity, salt, client_key_pair, server_public_key)
  ```

  From now on is to safe to create a new session between the client and server.

  ## Prime Groups

  The default prime size is 2048. Each prime group contains a large prime and a generator.
  These two values are used to derive several values on the calculations defined by the RFC.

  The 1024-, 1536-, and 2048-bit groups are taken from software developed by Tom
  Wu and Eugene Jhong for the Stanford SRP distribution, and subsequently proven
  to be prime. The larger primes are taken from
  [More Modular Exponential (MODP) Diffie-Hellman groups for Internet Key Exchange (IKE)](https://tools.ietf.org/html/rfc3526),
  but generators have been calculated that are primitive roots of N, unlike the generators in
  [More Modular Exponential (MODP) Diffie-Hellman groups for Internet Key Exchange (IKE)](https://tools.ietf.org/html/rfc3526).

  The following prime sizes are supported by SRP:

  - 1024
  - 1536
  - 2048
  - 3072
  - 4096
  - 6144
  - 8192

  ## Hash Algorithm

  By default the algorithm is SHA-1 because it is the algorithm used on the RFC.
  The SRP protocol uses a hash function to derive several values:

  - The hash of the public keys prevents an attacker who learns a user's verifier
    from being able to authenticate as that user.
  - The hash of the prime group prevents an attacker who can select group parameters
    from being able to launch a 2-for-1 guessing attack.
  - Another hash contains the user's password mixed with a salt.

  Cryptanalytic attacks against SHA-1 that only affect its collision-
  resistance do not compromise these uses.  If attacks against SHA-1
  are discovered that do compromise these uses, new cipher suites
  should be specified to use a different hash algorithm.

  The following hash algorithms are supported by SRP:

  - sha
  - sha224
  - sha256
  - sha384
  - sha512
  - md4
  - md5

  ## Shared options

  Almost all of the srp function below accept the following options:

  - `:prime_size` - The size of the prime to be used on the calculations (default: `2048`);
  - `:hash_algorithm` - The hash algorithm used to derive several values (default: `:sha`);
  - `:random_bytes` - Quantity of random bytes used internally (default: `32`)

  """

  import SRP.Math
  alias SRP.{Group, Identity, IdentityVerifier, KeyPair}
  require SRP.Group

  @default_options [prime_size: 2048, hash_algorithm: :sha, random_bytes: 32]

  @doc """
  Generate a identity verifier that should be passed to the server during account creation.

  ## Examples

      iex> alice_identity = SRP.new_identity("alice", "password123")
      iex> %SRP.IdentityVerifier{username: "alice", salt: salt, password_verifier: password_verifier} =
      ...>   SRP.generate_verifier(alice_identity)
      iex> is_binary(salt)
      true
      iex> is_binary(password_verifier)
      true

      iex> bob_identity = SRP.new_identity("bob", "password123")
      iex> %SRP.IdentityVerifier{username: "bob", salt: salt, password_verifier: password_verifier} =
      ...>   SRP.generate_verifier(bob_identity, hash_algorithm: :sha512)
      iex> is_binary(salt)
      true
      iex> is_binary(password_verifier)
      true

      iex> kirk_identity = SRP.new_identity("kirk", "password123")
      iex> %SRP.IdentityVerifier{username: "kirk", salt: salt, password_verifier: password_verifier} =
      ...>   SRP.generate_verifier(kirk_identity, prime_size: 1024)
      iex> is_binary(salt)
      true
      iex> is_binary(password_verifier)
      true

      iex> spock_identity = SRP.new_identity("spock", "password123")
      iex> %SRP.IdentityVerifier{username: "spock", salt: salt, password_verifier: password_verifier} =
      ...>   SRP.generate_verifier(spock_identity, prime_size: 8192, hash_algorithm: :sha256)
      iex> is_binary(salt)
      true
      iex> is_binary(password_verifier)
      true

  """
  @spec generate_verifier(Identity.t(), Keyword.t()) :: IdentityVerifier.t()
  def generate_verifier(%Identity{username: username, password: password}, options \\ []) do
    options = Keyword.merge(@default_options, options)
    prime_size = Keyword.get(options, :prime_size)
    hash_algorithm = Keyword.get(options, :hash_algorithm)
    random_bytes = Keyword.get(options, :random_bytes)

    %Group{prime: prime, generator: generator} = Group.get(prime_size)

    salt = random(random_bytes)
    credentials = hash(hash_algorithm, salt <> hash(hash_algorithm, username <> ":" <> password))
    password_verifier = mod_pow(generator, credentials, prime)

    IdentityVerifier.new(username, salt, password_verifier)
  end

  @doc """
  Create a new `SRP.Identity` struct.

  ## Examples

      iex> SRP.new_identity("alice", "password123")
      %SRP.Identity{username: "alice", password: "password123"}

  """
  def new_identity(username, password) when is_binary(username) and is_binary(password) do
    %Identity{
      username: username,
      password: password
    }
  end

  @doc """
  Generate a ephemeral key pair for the server.
  The private key is randomly generated, and the public key is
  derived from the private key and the password verifier.

  ## Examples

      iex> password_verifier = Base.decode16!("BEB25379D1A8581EB5A727673A2441EE")
      iex> %SRP.KeyPair{public: public_key, private: private_key} =
      ...>   SRP.server_key_pair(password_verifier)
      iex> is_binary(public_key)
      true
      iex> is_binary(private_key)
      true

      iex> password_verifier = Base.decode16!("BEB25379D1A8581EB5A727673A2441EE")
      iex> %SRP.KeyPair{public: public_key, private: private_key} =
      ...>   SRP.server_key_pair(password_verifier, hash_algorithm: :sha512)
      iex> is_binary(public_key)
      true
      iex> is_binary(private_key)
      true

      iex> password_verifier = Base.decode16!("BEB25379D1A8581EB5A727673A2441EE")
      iex> %SRP.KeyPair{public: public_key, private: private_key} =
      ...>   SRP.server_key_pair(password_verifier, prime_size: 1024)
      iex> is_binary(public_key)
      true
      iex> is_binary(private_key)
      true

      iex> password_verifier = Base.decode16!("BEB25379D1A8581EB5A727673A2441EE")
      iex> %SRP.KeyPair{public: public_key, private: private_key} =
      ...>   SRP.server_key_pair(password_verifier, prime_size: 8192, hash_algorithm: :sha256)
      iex> is_binary(public_key)
      true
      iex> is_binary(private_key)
      true

  """
  @spec server_key_pair(binary(), Keyword.t()) :: KeyPair.t()
  def server_key_pair(password_verifier, options \\ []) when is_binary(password_verifier) do
    options = Keyword.merge(@default_options, options)
    prime_size = Keyword.get(options, :prime_size)
    hash_algorithm = Keyword.get(options, :hash_algorithm)
    random_bytes = Keyword.get(options, :random_bytes)

    %Group{prime: prime, prime_length: prime_length, generator: generator} = Group.get(prime_size)

    multiplier = hash(hash_algorithm, prime <> String.pad_leading(generator, prime_length))
    private_key = random(random_bytes)

    public_key =
      add(
        mult(multiplier, password_verifier),
        mod_pow(generator, private_key, prime)
      )

    %KeyPair{private: private_key, public: :binary.encode_unsigned(public_key)}
  end

  @doc """
  Generate a ephemeral key pair for the client.
  The private key is randomly generated and
  then the public key is derived from the private key.

  ## Examples

      iex> %SRP.KeyPair{public: public_key, private: private_key} =
      ...>   SRP.client_key_pair()
      iex> is_binary(public_key)
      true
      iex> is_binary(private_key)
      true

      iex> %SRP.KeyPair{public: public_key, private: private_key} =
      ...>   SRP.client_key_pair(hash_algorithm: :sha512)
      iex> is_binary(public_key)
      true
      iex> is_binary(private_key)
      true

      iex> %SRP.KeyPair{public: public_key, private: private_key} =
      ...>   SRP.client_key_pair(prime_size: 1024)
      iex> is_binary(public_key)
      true
      iex> is_binary(private_key)
      true

      iex> %SRP.KeyPair{public: public_key, private: private_key} =
      ...>   SRP.client_key_pair(prime_size: 8192, hash_algorithm: :sha256)
      iex> is_binary(public_key)
      true
      iex> is_binary(private_key)
      true

  """
  @spec client_key_pair(Keyword.t()) :: KeyPair.t()
  def client_key_pair(options \\ []) do
    options = Keyword.merge(@default_options, options)
    prime_size = Keyword.get(options, :prime_size)
    random_bytes = Keyword.get(options, :random_bytes)

    %Group{prime: prime, generator: generator} = Group.get(prime_size)

    private_key = random(random_bytes)
    public_key = mod_pow(generator, private_key, prime)

    %KeyPair{private: private_key, public: public_key}
  end

  @doc """
  Generate a proof of identity for the client.

  ## Examples

      iex> identity = SRP.new_identity("bob", "password123")
      iex> identity_verifier = SRP.generate_verifier(identity)
      iex> client_key_pair = SRP.client_key_pair()
      iex> server_key_pair = SRP.server_key_pair(identity_verifier.password_verifier)
      iex> proof =
      ...>   SRP.client_proof(
      ...>     identity,
      ...>     identity_verifier.salt,
      ...>     client_key_pair,
      ...>     server_key_pair.public
      ...>   )
      iex> is_binary(proof)
      true

  """
  @spec client_proof(binary(), binary(), KeyPair.t(), binary(), Keyword.t()) :: binary()
  def client_proof(
        %Identity{} = identity,
        salt,
        %KeyPair{} = client_key_pair,
        server_public_key,
        options \\ []
      ) do
    premaster_secret =
      generate_client_premaster_secret(
        identity,
        salt,
        client_key_pair,
        server_public_key,
        options
      )

    generate_client_proof(client_key_pair.public, server_public_key, premaster_secret, options)
  end

  @doc """
  Validate the client's proof of identity.

  ## Examples

      iex> identity = SRP.new_identity("bob", "password123")
      iex> identity_verifier = SRP.generate_verifier(identity)
      iex> client_key_pair = SRP.client_key_pair()
      iex> server_key_pair = SRP.server_key_pair(identity_verifier.password_verifier)
      iex> client_proof =
      ...>  SRP.client_proof(
      ...>    identity,
      ...>    identity_verifier.salt,
      ...>    client_key_pair,
      ...>    server_key_pair.public
      ...>  )
      iex> SRP.valid_client_proof?(
      ...>   client_proof,
      ...>   identity_verifier.password_verifier,
      ...>   server_key_pair,
      ...>   client_key_pair.public
      ...> )
      true

  """
  @spec valid_client_proof?(binary(), binary(), KeyPair.t(), binary(), Keyword.t()) :: boolean()
  def valid_client_proof?(
        client_proof,
        password_verifier,
        %KeyPair{} = server_key_pair,
        client_public_key,
        options \\ []
      ) do
    premaster_secret =
      generate_server_premaster_secret(
        password_verifier,
        server_key_pair,
        client_public_key,
        options
      )

    client_proof ==
      generate_client_proof(client_public_key, server_key_pair.public, premaster_secret, options)
  end

  @doc """
  Generate a proof of identity for the server.

  ## Examples

      iex> identity = SRP.new_identity("bob", "password123")
      iex> identity_verifier = SRP.generate_verifier(identity)
      iex> client_key_pair = SRP.client_key_pair()
      iex> server_key_pair = SRP.server_key_pair(identity_verifier.password_verifier)
      iex> client_proof =
      ...>   SRP.client_proof(
      ...>     identity,
      ...>     identity_verifier.salt,
      ...>     client_key_pair,
      ...>     server_key_pair.public
      ...>   )
      iex> server_proof =
      ...>   SRP.server_proof(
      ...>     client_proof,
      ...>     identity_verifier.password_verifier,
      ...>     server_key_pair,
      ...>     client_key_pair.public
      ...>   )
      iex> is_binary(server_proof)
      true

  """
  @spec server_proof(binary(), binary(), KeyPair.t(), binary(), Keyword.t()) :: binary()
  def server_proof(
        client_proof,
        password_verifier,
        %KeyPair{} = server_key_pair,
        client_public_key,
        options \\ []
      ) do
    premaster_secret =
      generate_server_premaster_secret(
        password_verifier,
        server_key_pair,
        client_public_key,
        options
      )

    generate_server_proof(client_proof, client_public_key, premaster_secret, options)
  end

  @doc """
  Validate the server's proof of identity.

  ## Examples

      iex> identity = SRP.new_identity("bob", "password123")
      iex> identity_verifier = SRP.generate_verifier(identity)
      iex> client_key_pair = SRP.client_key_pair()
      iex> server_key_pair = SRP.server_key_pair(identity_verifier.password_verifier)
      iex> client_proof =
      ...>   SRP.client_proof(
      ...>     identity,
      ...>     identity_verifier.salt,
      ...>     client_key_pair,
      ...>     server_key_pair.public
      ...>   )
      iex> server_proof =
      ...>   SRP.server_proof(
      ...>     client_proof,
      ...>     identity_verifier.password_verifier,
      ...>     server_key_pair,
      ...>     client_key_pair.public
      ...>   )
      iex> SRP.valid_server_proof?(
      ...>   server_proof,
      ...>   identity,
      ...>   identity_verifier.salt,
      ...>   client_key_pair,
      ...>   server_key_pair.public
      ...> )
      true

  """
  @spec valid_server_proof?(binary(), Identity.t(), binary(), KeyPair.t(), binary(), Keyword.t()) ::
          boolean()
  def valid_server_proof?(
        server_proof,
        %Identity{} = identity,
        salt,
        %KeyPair{} = client_key_pair,
        server_public_key,
        options \\ []
      ) do
    premaster_secret =
      generate_client_premaster_secret(
        identity,
        salt,
        client_key_pair,
        server_public_key,
        options
      )

    client_proof =
      generate_client_proof(client_key_pair.public, server_public_key, premaster_secret, options)

    server_proof ==
      generate_server_proof(client_proof, client_key_pair.public, premaster_secret, options)
  end

  defp generate_client_premaster_secret(
         %Identity{username: username, password: password},
         salt,
         %KeyPair{} = client_key_pair,
         server_public_key,
         options
       )
       when is_binary(salt) and is_binary(server_public_key) do
    options = Keyword.merge(@default_options, options)
    prime_size = Keyword.get(options, :prime_size)
    hash_algorithm = Keyword.get(options, :hash_algorithm)

    %Group{prime: prime, prime_length: prime_length, generator: generator} = Group.get(prime_size)

    scrambling =
      hash(
        hash_algorithm,
        String.pad_leading(client_key_pair.public, prime_length) <>
          String.pad_leading(server_public_key, prime_length)
      )

    multiplier = hash(hash_algorithm, prime <> String.pad_leading(generator, prime_length))
    credentials = hash(hash_algorithm, salt <> hash(hash_algorithm, username <> ":" <> password))

    mod_pow(
      sub(server_public_key, mult(multiplier, mod_pow(generator, credentials, prime))),
      add(client_key_pair.private, mult(scrambling, credentials)),
      prime
    )
  end

  defp generate_server_premaster_secret(
         password_verifier,
         %KeyPair{} = server_key_pair,
         client_public_key,
         options
       )
       when is_binary(password_verifier) and is_binary(client_public_key) do
    options = Keyword.merge(@default_options, options)
    prime_size = Keyword.get(options, :prime_size)
    hash_algorithm = Keyword.get(options, :hash_algorithm)

    %Group{prime: prime, prime_length: prime_length} = Group.get(prime_size)

    scrambling =
      hash(
        hash_algorithm,
        String.pad_leading(client_public_key, prime_length) <>
          String.pad_leading(server_key_pair.public, prime_length)
      )

    mod_pow(
      mult(
        client_public_key,
        mod_pow(
          password_verifier,
          scrambling,
          prime
        )
      ),
      server_key_pair.private,
      prime
    )
  end

  defp generate_client_proof(
         client_public_key,
         server_public_key,
         premaster_secret,
         options
       ) do
    options = Keyword.merge(@default_options, options)
    hash_algorithm = Keyword.get(options, :hash_algorithm)

    hash(
      hash_algorithm,
      client_public_key <> server_public_key <> hash(hash_algorithm, premaster_secret)
    )
  end

  defp generate_server_proof(client_proof, client_public_key, premaster_secret, options) do
    options = Keyword.merge(@default_options, options)
    hash_algorithm = Keyword.get(options, :hash_algorithm)

    hash(
      hash_algorithm,
      client_public_key <> client_proof <> hash(hash_algorithm, premaster_secret)
    )
  end

  defp hash(type, value) when type in [:sha224, :sha256, :sha384, :sha512, :sha, :md5, :md4] do
    :crypto.hash(type, value)
  end

  defp random(bytes_quantity) when is_integer(bytes_quantity) do
    :crypto.strong_rand_bytes(bytes_quantity)
  end
end
