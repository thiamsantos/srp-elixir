defmodule SRP do
  @moduledoc """
  SRP implements the Secure Remote Password Protocol presented on
  [The SRP Authentication and Key Exchange System](https://tools.ietf.org/html/rfc2945)
  and [Using the Secure Remote Password (SRP) Protocol for TLS Authentication](https://tools.ietf.org/html/rfc5054).

  The protocol provides a way to do zero-knowledge authentication between client and servers.
  By using the SRP protocol you can:
  - authenticate without ever sending a password over the network.
  - authenticate without the risk of anyone learning any of your secrets – even
    if they intercept your communication.
  - authenticate both the identity of the client and the server to guarantee
    that a client isn’t communicating with an impostor server.

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
  - `:hash_algorithm` - The hash algorithm used to derive several values (default: `:sha`)

  """

  import SRP.Math
  alias SRP.{Group, Identity, KeyPair, Verifier}
  require SRP.Group

  @default_options [prime_size: 2048, hash_algorithm: :sha]

  @doc """
  Generate a identity verifier that should be passed to the server during account creation.

  ## Examples

      iex> alice_identity = SRP.Identity.new("alice", "password123")
      iex> %SRP.Verifier{username: "alice", salt: salt, password_verifier: password_verifier} =
      ...>   SRP.generate_verifier(alice_identity)
      iex> is_binary(salt)
      true
      iex> is_binary(password_verifier)
      true

      iex> bob_identity = SRP.Identity.new("bob", "password123")
      iex> %SRP.Verifier{username: "bob", salt: salt, password_verifier: password_verifier} =
      ...>   SRP.generate_verifier(bob_identity, hash_algorithm: :sha512)
      iex> is_binary(salt)
      true
      iex> is_binary(password_verifier)
      true

      iex> kirk_identity = SRP.Identity.new("kirk", "password123")
      iex> %SRP.Verifier{username: "kirk", salt: salt, password_verifier: password_verifier} =
      ...>   SRP.generate_verifier(kirk_identity, prime_size: 1024)
      iex> is_binary(salt)
      true
      iex> is_binary(password_verifier)
      true

      iex> spock_identity = SRP.Identity.new("spock", "password123")
      iex> %SRP.Verifier{username: "spock", salt: salt, password_verifier: password_verifier} =
      ...>   SRP.generate_verifier(spock_identity, prime_size: 8192, hash_algorithm: :sha256)
      iex> is_binary(salt)
      true
      iex> is_binary(password_verifier)
      true

  """
  @spec generate_verifier(Identity.t(), Keyword.t()) :: Verifier.t()
  def generate_verifier(%Identity{username: username, password: password}, options \\ []) do
    options = Keyword.merge(@default_options, options)
    prime_size = Keyword.get(options, :prime_size)
    hash_algorithm = Keyword.get(options, :hash_algorithm)

    %Group{prime: prime, generator: generator} = Group.get(prime_size)

    salt = random()
    credentials = hash(hash_algorithm, salt <> hash(hash_algorithm, username <> ":" <> password))
    password_verifier = mod_pow(generator, credentials, prime)

    %Verifier{
      username: username,
      salt: salt,
      password_verifier: password_verifier
    }
  end

  @spec server_key_pair(binary(), Keyword.t()) :: KeyPair.t()
  def server_key_pair(password_verifier, options \\ []) when is_binary(password_verifier) do
    options = Keyword.merge(@default_options, options)
    prime_size = Keyword.get(options, :prime_size)
    hash_algorithm = Keyword.get(options, :hash_algorithm)

    %Group{prime: prime, generator: generator} = Group.get(prime_size)

    multiplier = hash(hash_algorithm, prime <> generator)
    private_key = random()

    public_key =
      add(
        mult(multiplier, password_verifier),
        mod_pow(generator, private_key, prime)
      )

    %KeyPair{private: private_key, public: :binary.encode_unsigned(public_key)}
  end

  @spec client_key_pair(Keyword.t()) :: KeyPair.t()
  def client_key_pair(options \\ []) do
    options = Keyword.merge(@default_options, options)
    prime_size = Keyword.get(options, :prime_size)

    %Group{prime: prime, generator: generator} = Group.get(prime_size)

    private_key = random()
    public_key = mod_pow(generator, private_key, prime)

    %KeyPair{private: private_key, public: public_key}
  end

  @spec client_premaster_secret(
          Identity.t(),
          binary(),
          KeyPair.t(),
          binary(),
          Keyword.t()
        ) :: binary()
  def client_premaster_secret(
        %Identity{username: username, password: password},
        salt,
        %KeyPair{} = client,
        server_public_key,
        options \\ []
      )
      when is_binary(salt) and is_binary(server_public_key) do
    options = Keyword.merge(@default_options, options)
    prime_size = Keyword.get(options, :prime_size)
    hash_algorithm = Keyword.get(options, :hash_algorithm)

    %Group{prime: prime, generator: generator} = Group.get(prime_size)

    scrambling = hash(hash_algorithm, client.public <> server_public_key)
    multiplier = hash(hash_algorithm, prime <> generator)
    credentials = hash(hash_algorithm, salt <> hash(hash_algorithm, username <> ":" <> password))

    mod_pow(
      sub(server_public_key, mult(multiplier, mod_pow(generator, credentials, prime))),
      add(client.private, mult(scrambling, credentials)),
      prime
    )
  end

  @spec server_premaster_secret(binary(), KeyPair.t(), binary()) :: binary()
  def server_premaster_secret(
        password_verifier,
        %KeyPair{} = server,
        client_public_key,
        options \\ []
      )
      when is_binary(password_verifier) and is_binary(client_public_key) do
    options = Keyword.merge(@default_options, options)
    prime_size = Keyword.get(options, :prime_size)
    hash_algorithm = Keyword.get(options, :hash_algorithm)

    %Group{prime: prime} = Group.get(prime_size)

    scrambling = hash(hash_algorithm, client_public_key <> server.public)

    mod_pow(
      mult(
        client_public_key,
        mod_pow(
          password_verifier,
          scrambling,
          prime
        )
      ),
      server.private,
      prime
    )
  end

  def client_proof(client_public_key, server_public_key, premaster_secret, options \\ []) do
    options = Keyword.merge(@default_options, options)
    hash_algorithm = Keyword.get(options, :hash_algorithm)

    hash(
      hash_algorithm,
      client_public_key <> server_public_key <> hash(hash_algorithm, premaster_secret)
    )
  end

  def valid_client_proof?(
        client_proof,
        client_public_key,
        server_public_key,
        premaster_secret,
        options \\ []
      ) do
    client_proof == client_proof(client_public_key, server_public_key, premaster_secret, options)
  end

  def server_proof(client_proof, client_public_key, premaster_secret, options \\ []) do
    options = Keyword.merge(@default_options, options)
    hash_algorithm = Keyword.get(options, :hash_algorithm)

    hash(
      hash_algorithm,
      client_public_key <> client_proof <> hash(hash_algorithm, premaster_secret)
    )
  end

  def valid_server_proof?(
        server_proof,
        client_public_key,
        server_public_key,
        premaster_secret,
        options \\ []
      ) do
    client_proof = client_proof(client_public_key, server_public_key, premaster_secret, options)

    server_proof == server_proof(client_proof, client_public_key, premaster_secret, options)
  end

  defp hash(type, value) when type in [:sha224, :sha256, :sha384, :sha512, :sha, :md5, :md4] do
    :crypto.hash(type, value)
  end

  defp random do
    :crypto.strong_rand_bytes(256)
  end
end
