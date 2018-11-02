defmodule SRP.Identity do
  @moduledoc """
  A user identity is a struct formed by a username and a password.
  This identity is known only to the client. The server knowns only the `SRP.IdentityVerifier`.
  """
  defstruct [:username, :password]

  @type t :: %__MODULE__{username: String.t(), password: String.t()}

  @doc """
  Create a new `SRP.Identity` struct.

  ## Examples

      iex> SRP.Identity.new("alice", "password123")
      %SRP.Identity{username: "alice", password: "password123"}

  """
  def new(username, password) when is_binary(username) and is_binary(password) do
    %__MODULE__{
      username: username,
      password: password
    }
  end
end
