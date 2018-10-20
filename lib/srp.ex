defmodule Srp do
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

  alias SRP.Group

  # x = SHA(<salt> | SHA(<username> | ":" | <raw password>))
  # <password verifier> = v = g^x % N
  def generate_verifier(username, password, prime_size) do
    salt = :crypto.strong_rand_bytes(32)
    private_key = hash(salt <> hash(username <> ":" <> password))

    %Group{prime: prime, generator: generator} = Group.get(prime_size)

    password_verifier = :crypto.mod_pow(generator, private_key, prime)

    %{
      username: username,
      salt: salt,
      password_verifier: password_verifier
    }
  end

  # k = SHA1(N | PAD(g))
  # b = random()
  # B = k*v + g^b % N
  def server_key_pair(verifier, prime_size) do
    %Group{prime: prime, generator: generator} = Group.get(prime_size)
    private_key = :crypto.strong_rand_bytes(32)
    prime_key = :crypto.hash(:sha, prime <> to_string(generator))

    multiply = :binary.decode_unsigned(prime_key) * :binary.decode_unsigned(verifier)

    public_key =
      multiply + :binary.decode_unsigned(:crypto.mod_pow(generator, private_key, prime))

    %{private: private_key, public: :binary.encode_unsigned(public_key)}
  end

  # a = random()
  # A = g^a % N 
  def client_key_pair(prime_size) do
    %Group{prime: prime, generator: generator} = Group.get(prime_size)
    private_key = :crypto.strong_rand_bytes(32)

    public_key = :crypto.mod_pow(generator, private_key, prime)

    %{private: private_key, public: public_key}
  end

  # I, P = <read from user>
  # N, g, s, B = <read from server>
  # a = random()
  # A = g^a % N
  # u = SHA1(PAD(A) | PAD(B))
  # k = SHA1(N | PAD(g))
  # x = SHA1(s | SHA1(I | ":" | P))
  # <premaster secret> = (B - (k * g^x)) ^ (a + (u * x)) % N
  def client_premaster_secret(prime_size, salt, username, password, client, server) do
    # k = SHA1(prime | PAD(generator))
    # x = SHA1(salt | SHA1(username | ":" | password))
    # u = SHA1(PAD(client_public) | PAD(server_public))
    # (public_server - (k * generator ^ x)) ^ (client_private + (u * x)) % prime
    %Group{prime: prime, generator: generator} = Group.get(prime_size)

    first_hash = hash(prime <> to_string(generator))
    second_hash = hash(salt <> hash(username <> ":" <> password))
    third_hash = hash(client.public <> server.public)

    first =
      :binary.decode_unsigned(server.public) -
        :binary.decode_unsigned(first_hash) *
          :binary.decode_unsigned(:crypto.mod_pow(generator, second_hash, prime))

    second =
      :binary.decode_unsigned(client.private) +
        :binary.decode_unsigned(third_hash) * :binary.decode_unsigned(second_hash)

    :crypto.mod_pow(first, second, prime)
  end

  # N, g, s, v = <read from password file>
  # b = random()
  # k = SHA1(N | PAD(g))
  # B = k*v + g^b % N
  # A = <read from client>
  # u = SHA1(PAD(A) | PAD(B))
  # <premaster secret> = (A * v^u) ^ b % N
  def server_premaster_secret(prime_size, client, server, verifier) do
    # u = SHA1(PAD(client_public) | PAD(server_public))
    # <premaster secret> = (client_public * verifier^u) ^ server_private % prime

    %Group{prime: prime} = Group.get(prime_size)
    first_hash = hash(client.public <> server.public)

    first =
      :binary.decode_unsigned(client.public) *
        :binary.decode_unsigned(:crypto.mod_pow(verifier, first_hash, prime))

    :crypto.mod_pow(first, server.private, prime)
  end

  defp hash(value) do
    :crypto.hash(:sha, value)
  end
end
