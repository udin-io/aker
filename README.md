# Aker

Licences for on-premises Elixir apps: an install key held in a file or the
machine's TPM chip, signed activation requests, licence files signed by a
root key you trust, and a gate that checks the licence at boot and every hour.

The library holds no key of its own. Your app passes its product name and the
root public keys it trusts.

This first part covers the install key and the activation request. The licence
file and the gate follow before 0.1.0.

## The install key and an activation request

```elixir
dir = "/var/lib/my_app/licence"

# A key in the TPM chip when the machine has one, in a 0600 file otherwise.
install_key = Aker.InstallKey.for_dir(dir)
{module, opts} = install_key
{:ok, _public_key} = module.ensure(opts)

{:ok, machine_id_hash} = Aker.MachineId.hash("/etc/machine-id")

{:ok, request} =
  Aker.Request.build(
    product: "my_app",
    product_version: "1.2.0",
    install_key: install_key,
    machine_id_hash: machine_id_hash
  )

File.write!("activation-request.json", request)
```

The licensing server reads the request back with
`Aker.Request.verify(bytes, product: "my_app")`, which answers the install
public key and machine id hash only when the key the request names signed it.

## Installation

```elixir
def deps do
  [
    {:aker, github: "udin-io/aker"}
  ]
end
```

## Development

`bin/ci` runs every check CI runs. The TPM tests need `swtpm` and `tpm2-tools`;
run them with `mix test --only tpm`.

## Licence

Apache-2.0. See [LICENSE](LICENSE).
