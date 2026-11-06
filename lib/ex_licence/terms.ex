defmodule ExLicence.Terms do
  @moduledoc """
  What a verified licence says. Only `ExLicence.LicenceFile` builds one,
  after every signature and field passed, so holding one means a trusted
  root key's working key issued it for this install.

  `features` lists the features the licence sells beside its seats; a
  licence without the field reads as `[]`.
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
    :features
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
          features: [String.t()]
        }
end
