defmodule SRP do
  @moduledoc """
  Documentation for Srp.

  N - prime
  g - generator
  s - salt
  B - server public
  b - server private
  A - client public
  a - client private
  I - username (Identity)
  P - password
  v - verifier
  k - SRP-6 multiplier
  | - concatenation
  ^ - exponentiation
  % - integer remainder
  """

  import SRP.Math
  alias SRP.{Group, KeyPair, Verifier}
  require SRP.Group

  @default_options [prime_size: 2048, hash_algorithm: :sha]

  # x = SHA(<salt> | SHA(<username> | ":" | <raw password>))
  # <password verifier> = v = g^x % N
  @spec generate_verifier(String.t(), String.t(), Keyword.t()) :: Verifier.t()
  def generate_verifier(username, password, options \\ [])
      when is_bitstring(username) and is_bitstring(password) do
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

  # k = SHA1(N | PAD(g))
  # b = random()
  # B = k*v + g^b % N
  @spec server_key_pair(binary(), Keyword.t()) :: KeyPair.t()
  def server_key_pair(password_verifier, options \\ []) when is_binary(password_verifier) do
    options = Keyword.merge(@default_options, options)
    prime_size = Keyword.get(options, :prime_size)
    hash_algorithm = Keyword.get(options, :hash_algorithm)

    %Group{prime: prime, generator: generator} = Group.get(prime_size)

    private_key = random()

    public_key =
      add(
        mult(hash(hash_algorithm, prime <> generator), password_verifier),
        mod_pow(generator, private_key, prime)
      )

    %KeyPair{private: private_key, public: :binary.encode_unsigned(public_key)}
  end

  # a = random()
  # A = g^a % N 
  @spec client_key_pair(Keyword.t()) :: KeyPair.t()
  def client_key_pair(options \\ []) do
    options = Keyword.merge(@default_options, options)
    prime_size = Keyword.get(options, :prime_size)

    %Group{prime: prime, generator: generator} = Group.get(prime_size)

    private_key = random()
    public_key = mod_pow(generator, private_key, prime)

    %KeyPair{private: private_key, public: public_key}
  end

  # I, P = <read from user>
  # N, g, s, B = <read from server>
  # a = random()
  # A = g^a % N
  # u = SHA1(PAD(A) | PAD(B))
  # k = SHA1(N | PAD(g))
  # x = SHA1(s | SHA1(I | ":" | P))
  # <premaster secret> = (B - (k * g^x)) ^ (a + (u * x)) % N
  @spec client_premaster_secret(
          binary(),
          String.t(),
          String.t(),
          KeyPair.t(),
          binary(),
          Keyword.t()
        ) :: binary()
  def client_premaster_secret(
        salt,
        username,
        password,
        %KeyPair{} = client,
        server_public_key,
        options \\ []
      )
      when is_binary(salt) and is_bitstring(username) and is_bitstring(password) and
             is_binary(server_public_key) do
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

  # N, g, s, v = <read from password file>
  # b = random()
  # k = SHA1(N | PAD(g))
  # B = k*v + g^b % N
  # A = <read from client>
  # u = SHA1(PAD(A) | PAD(B))
  # <premaster secret> = (A * v^u) ^ b % N
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

  defp hash(type, value) when type in [:sha224, :sha256, :sha384, :sha512, :sha, :md5, :md4] do
    :crypto.hash(type, value)
  end

  defp random do
    :crypto.strong_rand_bytes(256)
  end
end
