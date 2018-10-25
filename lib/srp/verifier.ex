defmodule SRP.Verifier do
  @moduledoc """
  Verifier module.
  """

  @enforce_keys [:username, :salt, :password_verifier]
  defstruct [:username, :salt, :password_verifier]

  @type t :: %__MODULE__{username: String.t(), salt: binary(), password_verifier: binary()}
end
