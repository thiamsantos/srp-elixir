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

  # x = SHA(<salt> | SHA(<username> | ":" | <raw password>))
  # <password verifier> = v = g^x % N
  def generate_verifier(username, password, prime_size) do
    salt = :crypto.strong_rand_bytes(32)
    private_key = calculate_client_private_key(salt, username, password)

    {prime, generator} = get_group_parameters(prime_size)

    password_verifier = :crypto.mod_pow(generator, private_key, prime)

    %{
      username: username,
      salt: salt,
      password_verifier: password_verifier,
      prime_size: prime_size
    }
  end

  # k = SHA1(N | PAD(g))
  # b = random()
  # B = k*v + g^b % N
  def server_key_pair(verifier, prime_size) do
    {prime, generator} = get_group_parameters(prime_size)
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
    {prime, generator} = get_group_parameters(prime_size)
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
    {prime, generator} = get_group_parameters(prime_size)

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

    {prime, _generator} = get_group_parameters(prime_size)
    first_hash = hash(client.public <> server.public)

    first =
      :binary.decode_unsigned(client.public) *
        :binary.decode_unsigned(:crypto.mod_pow(verifier, first_hash, prime))

    :crypto.mod_pow(first, server.private, prime)
  end

  # SHA(<salt> | SHA(<username> | ":" | <raw password>))
  defp calculate_client_private_key(salt, username, password) do
    hash(salt <> hash(username <> ":" <> password))
  end

  defp hash(value) do
    :crypto.hash(:sha, value)
  end

  defp get_group_parameters(2048) do
    {"""
     AC6BDB41 324A9A9B F166DE5E 1389582F AF72B665 1987EE07 FC319294
       3DB56050 A37329CB B4A099ED 8193E075 7767A13D D52312AB 4B03310D
       CD7F48A9 DA04FD50 E8083969 EDB767B0 CF609517 9A163AB3 661A05FB
       D5FAAAE8 2918A996 2F0B93B8 55F97993 EC975EEA A80D740A DBF4FF74
       7359D041 D5C33EA7 1D281E44 6B14773B CA97B43A 23FB8016 76BD207A
       436C6481 F1D2B907 8717461A 5B9D32E6 88F87748 544523B5 24B0D57D
       5EA77A27 75D2ECFA 032CFBDB F52FB378 61602790 04E57AE6 AF874E73
       03CE5329 9CCC041C 7BC308D8 2A5698F3 A8D0C382 71AE35F8 E9DBFBB6
       94B5C803 D89F7AE4 35DE236D 525F5475 9B65E372 FCD68EF2 0FA7111F
       9E4AFF73
     """
     |> String.replace(~r/\s/m, "")
     |> String.upcase()
     |> Base.decode16!(), 2}
  end
end
