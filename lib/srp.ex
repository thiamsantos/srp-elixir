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

  import SRP.Math

  alias SRP.{Group, KeyPair, Verifier}

  # x = SHA(<salt> | SHA(<username> | ":" | <raw password>))
  # <password verifier> = v = g^x % N
  def generate_verifier(username, password, prime_size) do
    %Group{prime: prime, generator: generator} = Group.get(prime_size)

    salt = random()
    credentials = hash(salt <> hash(username <> ":" <> password))
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
  def server_key_pair(password_verifier, prime_size) do
    %Group{prime: prime, generator: generator} = Group.get(prime_size)

    private_key = random()

    public_key =
      add(
        mult(hash(prime <> generator), password_verifier),
        mod_pow(generator, private_key, prime)
      )

    %KeyPair{private: private_key, public: :binary.encode_unsigned(public_key)}
  end

  # a = random()
  # A = g^a % N 
  def client_key_pair(prime_size) do
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
  def client_premaster_secret(prime_size, salt, username, password, client, server_public_key) do
    %Group{prime: prime, generator: generator} = Group.get(prime_size)

    scrambling = hash(client.public <> server_public_key)
    multiplier = hash(prime <> generator)
    credentials = hash(salt <> hash(username <> ":" <> password))

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
  def server_premaster_secret(prime_size, client_public_key, server, password_verifier) do
    %Group{prime: prime} = Group.get(prime_size)

    scrambling = hash(client_public_key <> server.public)

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

  defp hash(value) do
    :crypto.hash(:sha512, value)
  end

  defp random do
    :crypto.strong_rand_bytes(32)
  end
end
