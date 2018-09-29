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

  def generate_salt do
    32
    |> :crypto.strong_rand_bytes()
    |> Base.encode32()
  end

  # x = SHA(<salt> | SHA(<username> | ":" | <raw password>))
  # <password verifier> = v = g^x % N
  def generate_verifier(username, password, prime_size, base) do
    salt = generate_salt()
    private_key = calculate_client_private_key(salt, username, password)

    {prime, generator} = get_group_parameters(prime_size)

    password_verifier = :crypto.mod_pow(generator, private_key, prime)

    %{
      username: encode(username, base),
      salt: encode(salt, base),
      password_verifier: encode(password_verifier, base),
      base: base,
      prime_size: prime_size
    }
  end

  # k = SHA1(N | PAD(g))
  # b = random()
  # B = k*v + g^b % N
  def server_key_pair(verifier, prime_size, base) do
    {prime, generator} = get_group_parameters(prime_size)
    private_key = rand_bytes()
    prime_key = :crypto.hash(:sha, encode(prime, 16) <> to_string(generator))

    multiply = :binary.decode_unsigned(prime_key) * :binary.decode_unsigned(private_key)

    public_key =
      multiply + :binary.decode_unsigned(:crypto.mod_pow(generator, private_key, prime))

    IO.inspect(private_key, label: :private_key)
    IO.inspect(public_key, label: :public_key)

    %{private: encode(private_key, base), public: Integer.to_string(public_key, 16)}
  end

  defp pow(a, b) do
    a
    |> :math.pow(b)
    |> round()
  end

  # A = g^a % N 
  def client_key_pair(prime_size, base)

  # I, P = <read from user>
  # N, g, s, B = <read from server>
  # a = random()
  # A = g^a % N
  # u = SHA1(PAD(A) | PAD(B))
  # k = SHA1(N | PAD(g))
  # x = SHA1(s | SHA1(I | ":" | P))
  # <premaster secret> = (B - (k * g^x)) ^ (a + (u * x)) % N
  def client_premaster_secret(
        server_public_key,
        prime_size,
        username,
        password,
        client_private_key,
        client_public_key,
        base
      )

  # N, g, s, v = <read from password file>
  # b = random()
  # k = SHA1(N | PAD(g))
  # B = k*v + g^b % N
  # A = <read from client>
  # u = SHA1(PAD(A) | PAD(B))
  # <premaster secret> = (A * v^u) ^ b % N
  def server_premaster_secret(
        verifier,
        prime_size,
        client_public_key,
        server_private_key,
        server_public_key,
        base
      )

  # SHA(<salt> | SHA(<username> | ":" | <raw password>))
  defp calculate_client_private_key(salt, username, password) do
    hash(salt <> hash(username <> ":" <> password))
  end

  defp hash(value) do
    :crypto.hash(:sha, value)
  end

  defp encode(value, 16) do
    Base.encode16(value)
  end

  defp encode(value, 32) do
    Base.encode16(value)
  end

  defp encode(value, 64) do
    Base.encode16(value)
  end

  defp decode(value, 16) do
    Base.decode16(value)
  end

  defp decode(value, 32) do
    Base.decode16(value)
  end

  defp decode(value, 64) do
    Base.decode16(value)
  end

  defp rand_bytes do
    :crypto.strong_rand_bytes(32)
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
