defmodule ExLicence do
  @moduledoc """
  Licences for on-premises Elixir apps.

    * `ExLicence.InstallKey` makes and holds the install key, in a file or
      the machine's TPM chip.
    * `ExLicence.MachineId` hashes the host's machine id.
    * `ExLicence.Request` builds and verifies the signed activation request.
    * `ExLicence.SigningKey` and `ExLicence.PublicKeys` read the Ed25519
      keys that sign and check licences.

  The library holds no key of its own: the app passes the root public keys
  it trusts.
  """
end
