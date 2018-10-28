defmodule SRP.Identity do
  defstruct [:username, :password]

  @type t :: %__MODULE__{username: String.t(), password: String.t()}

  def new(username, password) when is_bitstring(username) and is_bitstring(password) do
    %__MODULE__{
      username: username,
      password: password
    }
  end
end
