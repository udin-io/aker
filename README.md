# Aker

Licences for on-premises Elixir apps: an install key held in a file or the
machine's TPM chip, signed activation requests, licence files signed by a
root key you trust, and a gate that checks the licence at boot and every hour.

The library holds no key of its own. Your app passes its product name and the
root public keys it trusts.

Start with [the getting started guide](guides/getting_started.md). The wire
formats are in [the licence format guide](guides/licence_format.md).

## The gate

```elixir
children = [
  {Aker.Gate,
   name: MyApp.Licence,
   product: "my_app",
   product_version: "1.2.0",
   root_keys: root_keys,
   licence_dir: "/var/lib/my_app/licence",
   store: {MyApp.LicenceStore, []},
   server: [base_url: "https://licensing.example.com"],
   on_lock: &MyApp.Workers.stop_all/0}
]

Aker.Gate.locked?(MyApp.Licence)
# => true until a licence passes
```

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

## Checking a licence file

```elixir
{:ok, root_keys} = Aker.PublicKeys.decode(Application.fetch_env!(:my_app, :root_keys))

case Aker.LicenceFile.verify(File.read!("licence.json"),
       product: "my_app",
       root_keys: root_keys,
       install_key: install_key,
       machine_id_hash: machine_id_hash
     ) do
  {:ok, terms} -> terms.seats
  {:error, reason} -> reason
end
```

Each refusal has its own reason, such as `:unknown_root`, `:wrong_machine` or
`:term_ended`, and its own log line. An empty root key list refuses every file.

## Signing a licence on your own machine

```sh
mix aker.sign activation-request.json --product my_app \
  --root-key ../keys/root.pem --customer "Acme Logistics" --seats 10 \
  --term yearly --features reports,export
```

The task refuses a key inside the folder it runs in, and its last line prints
the root key's public half, which the app's root key list must hold.

## Installation

```elixir
def deps do
  [
    {:aker, "~> 0.1"}
  ]
end
```

## Development

`bin/ci` runs every check CI runs. The TPM tests need `swtpm` and `tpm2-tools`;
run them with `mix test --only tpm`.

## Licence

Apache-2.0. See [LICENSE](LICENSE).
