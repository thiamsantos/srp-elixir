defmodule SRP.KeyPair do
  @moduledoc """
  KeyPair module.
  """
  @enforce_keys [:private, :public]
  defstruct [:private, :public]

  @type t :: %__MODULE__{private: binary(), public: binary()}
end
