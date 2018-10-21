defmodule SRP.Math do
  @moduledoc false

  def sub(left, right) when is_binary(left) do
    sub(:binary.decode_unsigned(left), right)
  end

  def sub(left, right) when is_binary(right) do
    sub(left, :binary.decode_unsigned(right))
  end

  def sub(left, right) when is_integer(left) and is_integer(right) do
    left - right
  end

  def mult(left, right) when is_binary(left) do
    mult(:binary.decode_unsigned(left), right)
  end

  def mult(left, right) when is_binary(right) do
    mult(left, :binary.decode_unsigned(right))
  end

  def mult(left, right) when is_integer(left) and is_integer(right) do
    left * right
  end

  def add(left, right) when is_binary(left) do
    add(:binary.decode_unsigned(left), right)
  end

  def add(left, right) when is_binary(right) do
    add(left, :binary.decode_unsigned(right))
  end

  def add(left, right) when is_integer(left) and is_integer(right) do
    left + right
  end

  defdelegate mod_pow(value, exponent, modulus), to: :crypto
end
