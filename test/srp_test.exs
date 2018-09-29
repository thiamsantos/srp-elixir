defmodule SrpTest do
  use ExUnit.Case
  doctest Srp

  describe "generate_salt/0" do
    test "should generate a 256 bits salt" do
      actual = Srp.generate_salt() |> Base.decode32!() |> bit_size()
      expected = 256

      assert actual == expected
    end
  end

  describe "gen_verifier/2" do
    test "should generate an verifier" do
      prime_size = 2048
      base = 64

      verifier =
        Srp.generate_verifier("thiago@example.com", "P@ssw0rd", prime_size, base) |> IO.inspect()

      server_keys =
        Srp.server_key_pair(verifier.password_verifier, prime_size, base) |> IO.inspect()

      # IO.inspect()
    end
  end
end
