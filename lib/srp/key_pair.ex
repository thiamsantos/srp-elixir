defmodule SRP.KeyPair do
  @moduledoc """
  A pair of ephemeral keys, one public and one private.
  The private key is random and the public is derived from the private.
  This keys are exchanged during the process of authentication.
  """
  @enforce_keys [:private, :public]
  defstruct [:private, :public]

  @type t :: %__MODULE__{private: binary(), public: binary()}
end
