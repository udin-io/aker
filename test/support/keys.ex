defmodule ExLicence.TestSupport.Keys do
  @moduledoc """
  Keys for tests, made during the run. No key file is checked in.
  """

  alias ExLicence.InstallKey.Software
  alias ExLicence.MachineId
  alias ExLicence.SigningKey

  @doc "The PEM text `openssl genpkey -algorithm ed25519` writes for `seed`."
  def pem(seed) do
    der =
      <<0x30, 0x2E, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x70, 0x04, 0x22, 0x04,
        0x20>> <> seed

    "-----BEGIN PRIVATE KEY-----\n" <> Base.encode64(der) <> "\n-----END PRIVATE KEY-----\n"
  end

  @doc "A fresh Ed25519 signing key."
  def new_key do
    {:ok, key} = 32 |> :crypto.strong_rand_bytes() |> pem() |> SigningKey.from_pem()
    key
  end

  @doc """
  An install in `dir`: a software install key and a machine id file.
  Answers a map with `:install_key`, `:public_key`, `:machine_id_path`
  and `:machine_id_hash`.
  """
  def install(dir, machine_id \\ "4f1c0d9a2b3e4f5061728394a5b6c7d8") do
    File.mkdir_p!(dir)
    install_key = {Software, dir: Path.join(dir, "licence")}
    {:ok, public_key} = Software.ensure(elem(install_key, 1))
    machine_id_path = Path.join(dir, "machine-id")
    File.write!(machine_id_path, machine_id <> "\n")
    {:ok, machine_id_hash} = MachineId.hash(machine_id_path)

    %{
      install_key: install_key,
      public_key: public_key,
      machine_id_path: machine_id_path,
      machine_id_hash: machine_id_hash
    }
  end
end
