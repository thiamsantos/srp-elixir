defmodule SRP.Identity do
  @moduledoc """
  A user identity is a struct formed by a username and a password.
  This identity is known only to the client. The server knowns only the `SRP.IdentityVerifier`.
  """
  defstruct [:username, :password]

  @type t :: %__MODULE__{username: String.t(), password: String.t()}
end
