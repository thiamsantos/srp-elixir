defmodule SRP.IdentityVerifier do
  @moduledoc """
  A user identity verifier.
  This verifier is formed by the username, a random salt generated at registration time,
  and a password verifier derived from the user password.
  """

  @enforce_keys [:username, :salt, :password_verifier]
  defstruct [:username, :salt, :password_verifier]

  @type t :: %__MODULE__{username: String.t(), salt: binary(), password_verifier: binary()}

  @doc false
  def new(username, salt, password_verifier) when is_binary(username) and is_binary(salt) and is_binary(password_verifier) do
    %__MODULE__{
      username: username,
      salt: salt,
      password_verifier: password_verifier
    }
  end
end
