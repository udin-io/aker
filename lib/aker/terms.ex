defmodule Aker.Terms do
  @moduledoc """
  What a verified licence says. Only `Aker.LicenceFile` builds one,
  after every signature and field passed, so holding one means a trusted
  root key's working key issued it for this install.

  `features` lists the features the licence sells beside its seats; a
  licence without the field reads as `[]`.

  `limits` maps each named limit the licence sells to a whole number or
  `:unlimited`; a licence without the field reads as `%{}`. The product
  decides what each name counts. Read one with `limit/2`, which answers 0
  for a name the licence leaves out, so an older licence never unlocks a
  limit added after it was signed.
  """

  @enforce_keys [
    :licence_id,
    :serial,
    :customer_name,
    :install_public_key,
    :machine_id_hash,
    :term_start,
    :term_end,
    :seats,
    :moves_per_term,
    :issued_at,
    :working_key_id,
    :features,
    :limits
  ]
  defstruct @enforce_keys

  @type t :: %__MODULE__{
          licence_id: String.t(),
          serial: pos_integer(),
          customer_name: String.t(),
          install_public_key: binary(),
          machine_id_hash: String.t(),
          term_start: DateTime.t(),
          term_end: DateTime.t(),
          seats: non_neg_integer(),
          moves_per_term: non_neg_integer(),
          issued_at: DateTime.t(),
          working_key_id: String.t(),
          features: [String.t()],
          limits: %{String.t() => non_neg_integer() | :unlimited}
        }

  @doc "The number or `:unlimited` the licence sells for `name`, 0 when it names none."
  @spec limit(t(), String.t()) :: non_neg_integer() | :unlimited
  def limit(%__MODULE__{limits: limits}, name), do: Map.get(limits, name, 0)
end
