defmodule SRP.Verifier do
  @enforce_keys [:username, :salt, :password_verifier]
  defstruct [:username, :salt, :password_verifier]

  @type t :: %__MODULE__{username: String.t(), salt: binary(), password_verifier: binary()}
end
