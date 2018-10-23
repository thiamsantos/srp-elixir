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

  # x = SHA(<salt> | SHA(<username> | ":" | <raw password>))
  # <password verifier> = v = g^x % N
  @spec generate_verifier(integer(), String.t(), String.t(), binary()) :: Verifier.t()
  def generate_verifier(prime_size, username, password, salt \\ random())
      when prime_size in Group.valid_sizes() and is_bitstring(username) and is_bitstring(username) and
             is_bitstring(password) and is_binary(salt) do
    %Group{prime: prime, generator: generator} = Group.get(prime_size)

    credentials = hash(:sha, salt <> hash(:sha, username <> ":" <> password))
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
  @spec server_key_pair(integer(), binary(), binary()) :: KeyPair.t()
  def server_key_pair(prime_size, password_verifier, private_key \\ random())
      when prime_size in Group.valid_sizes() and is_binary(password_verifier) and
             is_binary(private_key) do
    %Group{prime: prime, generator: generator} = Group.get(prime_size)

    public_key =
      add(
        mult(hash(:sha, prime <> generator), password_verifier),
        mod_pow(generator, private_key, prime)
      )

    %KeyPair{private: private_key, public: :binary.encode_unsigned(public_key)}
  end

  # a = random()
  # A = g^a % N 
  @spec client_key_pair(integer(), binary()) :: KeyPair.t()
  def client_key_pair(prime_size, private_key \\ random())
      when prime_size in Group.valid_sizes() and is_binary(private_key) do
    %Group{prime: prime, generator: generator} = Group.get(prime_size)

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
          integer(),
          binary(),
          String.t(),
          String.t(),
          KeyPair.t(),
          binary()
        ) :: binary()
  def client_premaster_secret(
        prime_size,
        salt,
        username,
        password,
        %KeyPair{} = client,
        server_public_key
      )
      when prime_size in Group.valid_sizes() and is_binary(salt) and is_bitstring(username) and
             is_bitstring(password) and is_binary(server_public_key) do
    %Group{prime: prime, generator: generator} = Group.get(prime_size)

    scrambling = hash(:sha, client.public <> server_public_key)
    multiplier = hash(:sha, prime <> generator)
    credentials = hash(:sha, salt <> hash(:sha, username <> ":" <> password))

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
  @spec server_premaster_secret(integer(), binary(), KeyPair.t(), binary()) :: binary()
  def server_premaster_secret(
        prime_size,
        password_verifier,
        %KeyPair{} = server,
        client_public_key
      )
      when prime_size in Group.valid_sizes() and is_binary(password_verifier) and
             is_binary(client_public_key) do
    %Group{prime: prime} = Group.get(prime_size)

    scrambling = hash(:sha, client_public_key <> server.public)

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

  defp hash(type, value) when type in [:sha224, :sha256, :sha384, :sha, :md5, :md4] do
    :crypto.hash(type, value)
  end

  defp random do
    :crypto.strong_rand_bytes(256)
  end
end
