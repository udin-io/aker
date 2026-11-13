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

To tell the server about the running app at each renewal and refresh, pass
`check_in_fields`: a function that returns a map with string keys. The map
joins the call's body, so the install key signs it with the rest.

```elixir
check_in_fields: fn -> %{"running" => %{"version" => "2.4.1"}} end
```

The fields never replace the licence id or serial. The function runs in its
own process for at most 5 seconds. One that fails, runs longer, or returns a
map JSON cannot hold, non-string keys or more than 8 KB sends the call
without them, so a report never stops a renewal.

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
  limits: %{"clients" => 5, "messages_per_month" => :unlimited},
  licence_id: licence.id,
  term_start: term_start,
  term_end: term_end
)
```

A renewal passes the licence's own id and the next term, and a higher
`:serial`.

## 6. Read a named limit

A licence can sell named limits beside its seats. Your app decides what each
name counts, and reads it from the verified terms:

```elixir
Aker.Terms.limit(terms, "clients")
# => 5, :unlimited, or 0 when the licence names no such limit
```

## 7. Report what runs

`Aker.Fingerprint` hashes the code your install runs, for your app to send
with each renewal through the gate's `:check_in_fields`:

```elixir
check_in_fields: fn ->
  %{
    "release" => to_string(Aker.Fingerprint.cached_release(:my_app)),
    "loaded" => Aker.Fingerprint.loaded(modules: [MyApp.Licensing, MyAppWeb.LicenceLock])
  }
end
```

`release` hashes the release on disk and reads `not_a_release` outside one.
It skips each app's `priv/` except native libraries; list any other data
folder in `:exclude`. `loaded` hashes every aker module and the modules you
list. A build step can record the same value with
`Aker.Fingerprint.loaded_in_release(release_root, modules: [...])`. The
module uses only the standard library, so a script can load it from the
release's `ebin`. This is evidence for the licensing server, not a lock.

## 8. Refuse a customer build with the check off

Call `Aker.BuildCheck.check/1` when your app compiles and again when it
starts:

```elixir
Aker.BuildCheck.check(%{
  customer?: MyApp.Build.customer?(),
  enforced?: MyApp.Licensing.enforced?(),
  root_keys: System.get_env("MY_APP_LICENCE_ROOT_KEYS"),
  dev_keys: [MyApp.Licensing.dev_root_key()]
})
# => :ok, or {:error, :licence_check_off | :no_root_key | :bad_root_key | :dev_root_key}
```

Map each refusal to a sentence that names your own settings, and stop the
compile or the boot on it.
