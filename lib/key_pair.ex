defmodule SRP.KeyPair do
  @enforce_keys [:private, :public]
  defstruct [:private, :public]

  @type t :: %__MODULE__{private: binary(), public: binary()}
end
