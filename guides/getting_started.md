# Getting started

Aker holds no key of its own. Your app passes its product name, its version
and the root public keys it trusts, and decides itself what a lock blocks.

## 1. Keep the licence somewhere

The gate reads and writes the licence through a module that implements
`Aker.Store`. A record is any map or struct with `:envelope`, `:licence_id`,
`:serial`, `:term_end` and `:last_seen_at`.

```elixir
defmodule MyApp.LicenceStore do
  @behaviour Aker.Store

  @impl true
  def current(_opts), do: {:ok, MyApp.Repo.one(MyApp.Licence.newest())}

  @impl true
  def store(attrs, actor, _opts) do
    if actor == :system or MyApp.Accounts.admin?(actor),
      do: MyApp.Licence.insert(attrs),
      else: {:error, :forbidden}
  end

  @impl true
  def touch(record, last_seen_at, _opts), do: MyApp.Licence.touch(record, last_seen_at)
end
```

The gate passes the actor from your call to `store/3` untouched, and a
renewal stores as `:system`. Your store decides who may write.

## 2. Start the gate

```elixir
def gate_options do
  {:ok, root_keys} = Aker.PublicKeys.decode(Application.fetch_env!(:my_app, :root_keys))

  [
    name: MyApp.Licence,
    product: "my_app",
    product_version: to_string(Application.spec(:my_app, :vsn)),
    root_keys: root_keys,
    licence_dir: System.get_env("MY_APP_LICENCE_DIR"),
    machine_id_path: System.get_env("MY_APP_MACHINE_ID_PATH"),
    store: {MyApp.LicenceStore, []},
    server: [base_url: "https://licensing.example.com"],
    on_lock: &MyApp.Workers.stop_all/0,
    on_unlock: &MyApp.Workers.start_all/0,
    settings: [licence_dir: "MY_APP_LICENCE_DIR", machine_id_path: "MY_APP_MACHINE_ID_PATH"]
  ]
end

# In your application's children:
{Aker.Gate, MyApp.gate_options()}
```

The gate checks the licence at boot, then every hour. In the term's last
week each hourly tick asks the server for the next term's licence.

## 3. Read the lock

```elixir
Aker.Gate.locked?(MyApp.Licence)
# => true until a licence passes
```

A gate name no check has run under reads `{:locked, :not_checked}`, so an app
that never starts the gate runs locked. Read the status on each page or job
that the licence guards.

## 4. Activate, load and refresh

```elixir
Aker.Gate.activate(MyApp.gate_options(), "ABCD-EFGH-2345", current_user)
Aker.Gate.load(MyApp.gate_options(), File.read!("licence.json"), current_user)
Aker.Gate.refresh(MyApp.gate_options(), current_user)
```

These trust your app to have checked who may call them. Check the caller
before you call.

## 5. Sign licences on a server

A licensing server holds a working key and its certificate, never the root
key. Certify the working key offline with `mix aker.certify` (see the licence
format guide), then sign with it:

```elixir
{:ok, certificate} = Aker.Issuer.decode_certificate(System.fetch_env!("WORKING_CERTIFICATE"))

Aker.Issuer.issue(request_bytes,
  product: "my_app",
  working_key: working_key,
  certificate: certificate,
  root_keys: root_keys,
  customer: "Acme Logistics",
  seats: 10,
  licence_id: licence.id,
  term_start: term_start,
  term_end: term_end
)
```

A renewal passes the licence's own id and the next term, and a higher
`:serial`.
