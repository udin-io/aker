defmodule Aker do
  @moduledoc """
  Licences for on-premises Elixir apps.

    * `Aker.InstallKey` makes and holds the install key, in a file or
      the machine's TPM chip.
    * `Aker.MachineId` hashes the host's machine id.
    * `Aker.Request` builds and verifies the signed activation request.
    * `Aker.SigningKey` and `Aker.PublicKeys` read the Ed25519
      keys that sign and check licences.

  The library holds no key of its own: the app passes the root public keys
  it trusts.
  """
end
