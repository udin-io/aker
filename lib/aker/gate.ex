defmodule Aker.Gate do
  @moduledoc """
  Whether this install may run. The gate checks the stored licence at boot
  and every hour, holds `:licensed` or `{:locked, reason}` where every
  reader finds it without a call, and renews the licence in its term's
  last week.

  The host starts one gate in its supervision tree, with the options below,
  and decides what a lock blocks: it reads `status/1` or `locked?/1` on each
  page or job, and the gate calls `:on_lock` and `:on_unlock` when the
  install locks or unlocks. A gate name no check has run under reads
  `{:locked, :not_checked}`, so a host that forgets to start the gate runs
  locked, not free.

  Every function takes the gate's options, so a host can build them from
  runtime config at each call. The process only runs the boot check and the
  hourly tick.

  `load/3`, `activate/3` and `refresh/2` trust the host to have checked who
  may call them; the actor passes to the store untouched. `renew/1` stores
  as `:system`.

  A running install stays licensed through a failure of its own machine (a
  store it cannot read, a missing machine id, a slow chip): only the licence
  itself locks a running install. A booting install stays locked until the
  check passes.
  """

  use GenServer

  require Logger

  alias Aker.Client
  alias Aker.InstallKey
  alias Aker.LicenceFile
  alias Aker.MachineId
  alias Aker.Request

  @passing_failures [
    :store_unreadable,
    :no_licence_dir,
    :machine_id_missing,
    :machine_id_not_mounted,
    :install_key_missing,
    :install_key_unreadable,
    :install_key_unwritable,
    :install_key_timeout,
    :install_key_proof_failed
  ]
  # An activation code: base32 or base64url characters, dashes and padding.
  @code ~r/\A[A-Za-z0-9_=-]{1,64}\z/

  @schema NimbleOptions.new!(
            name: [
              type: :atom,
              required: true,
              doc: "The gate's name; its status is kept under it."
            ],
            product: [type: :string, required: true, doc: "The product this app is."],
            product_version: [type: :string, required: true, doc: "The app's version."],
            root_keys: [
              type: {:list, :string},
              required: true,
              doc: "The trusted Ed25519 root public keys, raw (`Aker.PublicKeys.decode/1`)."
            ],
            licence_dir: [
              type: {:or, [:string, nil]},
              doc: "The folder that holds the install key."
            ],
            machine_id_path: [
              type: {:or, [:string, nil]},
              doc: "The host's machine id file (default `/etc/machine-id`)."
            ],
            require_mount: [
              type: :boolean,
              default: false,
              doc:
                "Refuse with `:machine_id_not_mounted` unless `:machine_id_path` is given, " <>
                  "for a container whose own `/etc/machine-id` every copy shares."
            ],
            store: [
              type: {:tuple, [:atom, :keyword_list]},
              required: true,
              doc: "`{module, opts}` of an `Aker.Store`."
            ],
            server: [type: :keyword_list, default: [], doc: "`Aker.Client`'s server options."],
            on_lock: [type: {:fun, 0}, doc: "Called when a running install locks."],
            on_unlock: [type: {:fun, 0}, doc: "Called when a locked install unlocks."],
            check_every: [
              type: :pos_integer,
              default: :timer.hours(1),
              doc: "Milliseconds between ticks."
            ],
            renew_within: [
              type: :pos_integer,
              default: 7 * 24 * 60 * 60,
              doc: "Seconds before the term ends when each tick renews."
            ],
            tpm_device: [type: :string, default: "/dev/tpmrm0", doc: "The TPM chip's device."],
            tpm_options: [type: :keyword_list, default: [], doc: "`Aker.InstallKey.Tpm` options."],
            settings: [
              type: :keyword_list,
              default: [],
              doc:
                "The setting names a log line tells the operator to set, for `:licence_dir`, " <>
                  "`:machine_id_path` and `:server_url` (default each option's own name)."
            ],
            now: [type: {:struct, DateTime}, doc: "The time to check against, for tests."]
          )

  @type status :: :licensed | {:locked, atom()}

  @doc "The options every function takes:\n\n#{NimbleOptions.docs(@schema)}"
  @spec options() :: NimbleOptions.t()
  def options, do: @schema

  @doc "The install's licence status under `name`."
  @spec status(atom()) :: status()
  def status(name), do: :persistent_term.get({__MODULE__, name}, {:locked, :not_checked})

  @doc "Whether the install is locked."
  @spec locked?(atom()) :: boolean()
  def locked?(name), do: status(name) != :licensed

  @doc "Forgets the status under `name`, which then reads `{:locked, :not_checked}`."
  @spec reset(atom()) :: :ok
  def reset(name) do
    :persistent_term.erase({__MODULE__, name})
    :ok
  end

  defp put_status(name, status) do
    if :persistent_term.get({__MODULE__, name}, nil) != status,
      do: :persistent_term.put({__MODULE__, name}, status)

    status
  end

  @doc """
  This install's key and machine id hash, or the reason they are missing.
  Makes the install key when there is none.
  """
  @spec context(keyword()) ::
          {:ok, %{install_key: {module(), keyword()}, machine_id_hash: String.t()}}
          | {:error, atom()}
  def context(opts) do
    opts = validate!(opts)

    with {:ok, dir} <- licence_dir(opts),
         {:ok, path} <- machine_id_path(opts),
         install_key =
           InstallKey.for_dir(dir, tpm_device: opts[:tpm_device], tpm_options: opts[:tpm_options]),
         {:ok, _public_key} <- ensure(install_key),
         {:ok, machine_id_hash} <- MachineId.hash(path) do
      {:ok, %{install_key: install_key, machine_id_hash: machine_id_hash}}
    end
  end

  defp licence_dir(opts) do
    case opts[:licence_dir] do
      dir when is_binary(dir) and dir != "" -> {:ok, dir}
      _unset -> {:error, :no_licence_dir}
    end
  end

  defp machine_id_path(opts) do
    case {opts[:machine_id_path], opts[:require_mount]} do
      {path, _require} when is_binary(path) and path != "" -> {:ok, path}
      {_unset, true} -> {:error, :machine_id_not_mounted}
      {_unset, false} -> {:ok, "/etc/machine-id"}
    end
  end

  defp ensure({module, key_opts}), do: module.ensure(key_opts)

  @doc "The activation request to send the licensing server, as the file's bytes."
  @spec request(keyword()) :: {:ok, binary()} | {:error, atom()}
  def request(opts) do
    opts = validate!(opts)

    with {:ok, context} <- context(opts) do
      Request.build(
        product: opts[:product],
        product_version: opts[:product_version],
        install_key: context.install_key,
        machine_id_hash: context.machine_id_hash
      )
    end
  end

  @doc "The licence in force, or nil when none is stored or the store cannot be read."
  @spec current(keyword()) :: map() | nil
  def current(opts) do
    case fetch_current(validate!(opts)) do
      {:ok, record} -> record
      {:error, _reason} -> nil
    end
  end

  @doc """
  Checks `bytes` as this install's licence and stores it as `actor`. The
  install unlocks when it passes, and `:on_unlock` runs when it was locked.
  """
  @spec load(keyword(), binary(), term()) :: {:ok, map()} | {:error, term()}
  def load(opts, bytes, actor) do
    opts = validate!(opts)
    now = now(opts)

    with {:ok, current} <- fetch_current(opts),
         {:ok, context} <- context(opts),
         {:ok, terms} <-
           LicenceFile.verify(bytes,
             product: opts[:product],
             root_keys: opts[:root_keys],
             install_key: context.install_key,
             machine_id_hash: context.machine_id_hash,
             now: now,
             last_seen: current && current.last_seen_at,
             stored_serial: current && current.serial
           ),
         {:ok, record} <- store(opts, bytes, terms, latest(now, current), actor) do
      was_locked? = locked?(opts[:name])
      put_status(opts[:name], :licensed)
      Logger.info("licence loaded: #{terms.licence_id}, serial #{terms.serial}")
      if was_locked?, do: callback(opts, :on_unlock)
      {:ok, record}
    end
  end

  @doc """
  Activates with `code` as `actor`: sends this install's request to the
  licensing server and loads the licence that comes back. A code that is
  not 1 to 64 base32 or base64url characters makes no call.
  """
  @spec activate(keyword(), String.t(), term()) :: {:ok, map()} | {:error, term()}
  def activate(opts, code, actor) do
    opts = validate!(opts)
    code = if is_binary(code), do: String.trim(code), else: ""

    with true <- (byte_size(code) <= 64 and Regex.match?(@code, code)) || {:error, :bad_code},
         {:ok, request} <- request(opts),
         {:ok, bytes} <- Client.activate(server(opts), code, request) do
      load(opts, bytes, actor)
    end
  end

  @doc "Asks for this term's licence with the current seats, as `actor`, and loads it."
  @spec refresh(keyword(), term()) :: {:ok, map()} | {:error, term()}
  def refresh(opts, actor), do: check_in(validate!(opts), &Client.refresh/3, actor)

  @doc "Asks for the next term's licence and loads it, as `:system`."
  @spec renew(keyword()) :: {:ok, map()} | {:error, term()}
  def renew(opts), do: check_in(validate!(opts), &Client.renew/3, :system)

  defp check_in(opts, call, actor) do
    with {:ok, current} <- fetch_current(opts),
         %{} <- current || {:error, :no_licence},
         {:ok, context} <- context(opts),
         {:ok, bytes} <- call.(server(opts), context.install_key, current) do
      load(opts, bytes, actor)
    end
  end

  defp server(opts) do
    Keyword.put_new(opts[:server], :setting, setting(opts, :server_url))
  end

  defp store(opts, bytes, terms, last_seen, actor) do
    {module, store_opts} = opts[:store]

    attrs = %{
      envelope: bytes,
      licence_id: terms.licence_id,
      serial: terms.serial,
      customer_name: terms.customer_name,
      seats: terms.seats,
      features: terms.features,
      term_start: terms.term_start,
      term_end: terms.term_end,
      last_seen_at: last_seen
    }

    case module.store(attrs, actor, store_opts) do
      {:ok, record} -> {:ok, record}
      {:error, :forbidden} -> {:error, :forbidden}
      _other -> {:error, :not_stored}
    end
  end

  # A store that cannot be read is its own refusal, never "no licence".
  defp fetch_current(opts) do
    {module, store_opts} = opts[:store]

    case module.current(store_opts) do
      {:ok, record} when is_map(record) or is_nil(record) ->
        {:ok, record}

      other ->
        Logger.error("licence: cannot read the stored licence: #{inspect(other)}")
        {:error, :store_unreadable}
    end
  end

  @doc "Runs the boot check now and answers the status it holds."
  @spec check(keyword()) :: status()
  def check(opts) do
    opts = validate!(opts)
    put_status(opts[:name], evaluate(opts))
  end

  defp evaluate(opts) do
    now = now(opts)

    with {:ok, context} <- context(opts),
         {:ok, record} <- fetch_current(opts),
         %{} <- record || {:error, :no_licence},
         {:ok, _terms} <-
           LicenceFile.verify(record.envelope,
             product: opts[:product],
             root_keys: opts[:root_keys],
             install_key: context.install_key,
             machine_id_hash: context.machine_id_hash,
             now: now,
             last_seen: record.last_seen_at
           ) do
      touch(opts, record, now)
      :licensed
    else
      {:error, reason} ->
        explain(opts, reason)
        {:locked, reason}
    end
  end

  @doc """
  The hourly check: the boot check again, which also moves the latest time
  seen. A running install it finds locked by the licence itself calls
  `:on_lock`; a locked install it finds licensed calls `:on_unlock`.
  """
  @spec recheck(keyword()) :: status()
  def recheck(opts) do
    opts = validate!(opts)
    name = opts[:name]
    was_locked? = locked?(name)

    case {was_locked?, evaluate(opts)} do
      {false, {:locked, reason}} when reason in @passing_failures ->
        Logger.warning("licence: hourly check could not run (#{reason}); still licensed")
        :licensed

      {false, {:locked, _reason} = locked} ->
        put_status(name, locked)
        callback(opts, :on_lock)
        locked

      {true, :licensed} ->
        put_status(name, :licensed)
        callback(opts, :on_unlock)
        :licensed

      {_was_locked?, status} ->
        put_status(name, status)
    end
  end

  @doc """
  One tick: renews when the licence's term ends within `:renew_within`,
  whatever the lock state, so a paid renewal unlocks an install whose term
  ended, then runs `recheck/1`. One renewal call per tick, with no retry:
  the next tick is the retry.
  """
  @spec tick(keyword()) :: status()
  def tick(opts) do
    opts = validate!(opts)
    _ = maybe_renew(opts)
    recheck(opts)
  end

  defp maybe_renew(opts) do
    with {:ok, %{term_end: %DateTime{} = term_end}} <- fetch_current(opts),
         true <- DateTime.diff(term_end, now(opts)) <= opts[:renew_within] do
      case renew(opts) do
        {:ok, _record} ->
          :renewed

        {:error, reason} = error ->
          Logger.warning("licence: renewal failed: #{inspect(reason)}; the next tick tries again")
          error
      end
    else
      _not_due -> :not_due
    end
  end

  # The refusals LicenceFile does not log itself.
  defp explain(opts, :no_licence_dir),
    do: Logger.error("licence: no licence folder. Set #{setting(opts, :licence_dir)}.")

  defp explain(opts, :machine_id_missing),
    do:
      Logger.error(
        "licence: no machine id file. Mount the host's /etc/machine-id or set " <>
          "#{setting(opts, :machine_id_path)}."
      )

  defp explain(opts, :machine_id_not_mounted),
    do:
      Logger.error(
        "licence: the host's machine id is not mounted. Mount /etc/machine-id read-only " <>
          "and set #{setting(opts, :machine_id_path)} to it."
      )

  defp explain(_opts, :install_key_missing),
    do: Logger.error("licence: install_key_missing, the key this install made is not there")

  defp explain(_opts, :install_key_timeout),
    do: Logger.error("licence: install_key_timeout, the TPM chip did not answer in time")

  defp explain(_opts, :no_licence), do: Logger.warning("licence: none loaded yet")

  defp explain(opts, reason) when reason in [:install_key_unwritable, :install_key_unreadable],
    do: Logger.error("licence: install key #{reason} in #{setting(opts, :licence_dir)}")

  defp explain(_opts, _logged_by_licence_file), do: :ok

  defp setting(opts, key), do: Keyword.get(opts[:settings], key, Atom.to_string(key))

  defp touch(opts, record, now) do
    {module, store_opts} = opts[:store]
    module.touch(record, latest(now, record), store_opts)
  end

  defp latest(now, nil), do: DateTime.truncate(now, :second)

  defp latest(now, %{last_seen_at: %DateTime{} = seen}),
    do: if(DateTime.compare(now, seen) == :gt, do: DateTime.truncate(now, :second), else: seen)

  defp latest(now, _record), do: DateTime.truncate(now, :second)

  defp now(opts), do: opts[:now] || DateTime.utc_now()

  defp callback(opts, key) do
    case opts[key] do
      nil -> :ok
      fun -> fun.()
    end
  end

  defp validate!(opts), do: NimbleOptions.validate!(opts, @schema)

  # The process: the boot check, then a tick each `:check_every`, so a term
  # that ends while the app runs locks it within the hour, and a boot that
  # met a store outage unlocks once the store answers.

  @doc false
  def child_spec(opts) do
    %{id: {__MODULE__, Keyword.fetch!(opts, :name)}, start: {__MODULE__, :start_link, [opts]}}
  end

  @doc "Starts the gate: the boot check now, then a tick each `:check_every`."
  @spec start_link(keyword()) :: GenServer.on_start()
  def start_link(opts) do
    opts = validate!(opts)
    GenServer.start_link(__MODULE__, opts, name: opts[:name])
  end

  @impl true
  def init(opts) do
    check(opts)
    Process.send_after(self(), :tick, opts[:check_every])
    {:ok, opts}
  end

  @impl true
  def handle_info(:tick, opts) do
    tick(opts)
    Process.send_after(self(), :tick, opts[:check_every])
    {:noreply, opts}
  end
end
