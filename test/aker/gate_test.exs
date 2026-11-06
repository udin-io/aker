defmodule Aker.GateTest do
  @moduledoc """
  The gate checks the stored licence at boot and each tick, stays locked
  until a licence passes, renews in the term's last week, and calls the
  host back when the install locks or unlocks. The licensing server is
  `Aker.TestSupport.LicensingServer`, which checks each signed call
  with `Aker.SignedCall`.
  """
  use ExUnit.Case, async: true

  import ExUnit.CaptureLog
  import Aker.TestSupport.Keys
  import Aker.TestSupport.Licences

  alias Aker.Gate
  alias Aker.Request
  alias Aker.TestSupport.AgentStore
  alias Aker.TestSupport.LicensingServer

  @moduletag :tmp_dir
  @moduletag :capture_log

  setup %{tmp_dir: dir} do
    install = install(dir)
    store = AgentStore.start()
    test = self()
    name = :"gate_#{System.unique_integer([:positive])}"
    on_exit(fn -> Gate.reset(name) end)

    opts = [
      name: name,
      product: product(),
      product_version: "2.4.1",
      root_keys: [root_public_key()],
      licence_dir: Path.join(dir, "licence"),
      machine_id_path: install.machine_id_path,
      store: store,
      server: LicensingServer.server(),
      on_lock: fn -> send(test, :locked) end,
      on_unlock: fn -> send(test, :unlocked) end
    ]

    %{install: install, store: store, opts: opts, name: name}
  end

  defp in_days(days),
    do: DateTime.utc_now() |> DateTime.add(days, :day) |> DateTime.truncate(:second)

  defp iso(time), do: DateTime.to_iso8601(time)

  # A stored licence whose term ends `days` from now, the gate licensed.
  defp licensed!(ctx, days, serial \\ 1) do
    bytes = licence(ctx.install, fields: %{"serial" => serial, "term_end" => iso(in_days(days))})
    {:ok, record} = Gate.load(ctx.opts, bytes, :admin)
    assert_received :unlocked
    record
  end

  describe "the lock" do
    test "a gate name never checked reads locked, not_checked", ctx do
      assert Gate.status(ctx.name) == {:locked, :not_checked}
      assert Gate.locked?(ctx.name)

      licensed!(ctx, 20)
      assert Gate.status(ctx.name) == :licensed
    end

    test "no licence locks with no_licence", ctx do
      assert capture_log(fn -> assert Gate.check(ctx.opts) == {:locked, :no_licence} end) =~
               "none loaded yet"

      assert Gate.locked?(ctx.name)
    end

    test "a valid licence reads licensed and calls on_unlock once when it was locked", ctx do
      {:locked, :no_licence} = Gate.check(ctx.opts)

      assert {:ok, %{serial: 1, customer_name: "Acme Logistics"}} =
               Gate.load(ctx.opts, licence(ctx.install), :admin)

      assert Gate.status(ctx.name) == :licensed
      assert_received :unlocked

      # Already licensed: a newer licence unlocks nothing again.
      {:ok, _record} = Gate.load(ctx.opts, licence(ctx.install, fields: %{"serial" => 2}), :admin)
      refute_received :unlocked

      # A boot reads the stored licence and stays licensed.
      assert Gate.check(ctx.opts) == :licensed
    end

    test "a store that answers forbidden makes load answer forbidden and stores nothing", ctx do
      {:locked, :no_licence} = Gate.check(ctx.opts)
      bytes = licence(ctx.install)

      assert Gate.load(ctx.opts, bytes, :stranger) == {:error, :forbidden}
      assert AgentStore.rows(ctx.store) == []
      assert Gate.locked?(ctx.name)
      refute_received :unlocked

      assert {:ok, _record} = Gate.load(ctx.opts, bytes, :admin)
      assert [_row] = AgentStore.rows(ctx.store)
    end

    test "a licence for another machine is refused, loaded or stored", ctx do
      other = install(Path.join(ctx.tmp_dir, "other"), "0000aaaa0000aaaa0000aaaa0000aaaa")
      bytes = licence(ctx.install, fields: %{"machine_id_hash" => other.machine_id_hash})

      assert Gate.load(ctx.opts, bytes, :admin) == {:error, :wrong_machine}
      assert AgentStore.rows(ctx.store) == []

      # A licence stored for this machine, then the disk moved to another.
      licensed!(ctx, 20)
      File.write!(ctx.install.machine_id_path, "0000aaaa0000aaaa0000aaaa0000aaaa\n")
      assert Gate.check(ctx.opts) == {:locked, :wrong_machine}
    end

    test "a licence older than the one stored is refused", ctx do
      licensed!(ctx, 20, 3)

      assert Gate.load(ctx.opts, licence(ctx.install, fields: %{"serial" => 2}), :admin) ==
               {:error, :older_serial}

      assert {:ok, %{serial: 3}} =
               Gate.load(ctx.opts, licence(ctx.install, fields: %{"serial" => 3}), :admin)
    end

    test "a boot remembers the latest time seen, so a clock set back is refused", ctx do
      licensed!(ctx, 20)
      assert Gate.check(ctx.opts) == :licensed

      assert Gate.check(Keyword.put(ctx.opts, :now, DateTime.add(DateTime.utc_now(), 3, :day))) ==
               :licensed

      assert Gate.check(ctx.opts) == {:locked, :clock_behind}
    end

    test "with no licence folder it locks and names the operator's setting", ctx do
      opts =
        ctx.opts
        |> Keyword.put(:licence_dir, nil)
        |> Keyword.put(:settings, licence_dir: "ACME_LICENCE_DIR")

      log = capture_log(fn -> assert Gate.check(opts) == {:locked, :no_licence_dir} end)
      assert log =~ "Set ACME_LICENCE_DIR."
    end

    test "require_mount refuses a default machine id path, and takes a given one", ctx do
      opts = ctx.opts |> Keyword.delete(:machine_id_path) |> Keyword.put(:require_mount, true)

      log = capture_log(fn -> assert Gate.check(opts) == {:locked, :machine_id_not_mounted} end)
      assert log =~ "set machine_id_path"

      assert Gate.check(Keyword.put(ctx.opts, :require_mount, true)) == {:locked, :no_licence}
    end

    test "with no machine id it locks and names the setting", ctx do
      File.rm!(ctx.install.machine_id_path)

      log = capture_log(fn -> assert Gate.check(ctx.opts) == {:locked, :machine_id_missing} end)
      assert log =~ "machine_id_path"
    end

    test "a store that cannot be read locks a boot as store_unreadable, never no_licence",
         ctx do
      {AgentStore, store_opts} = ctx.store

      opts =
        Keyword.put(ctx.opts, :store, {AgentStore, Keyword.put(store_opts, :fail_reads, true)})

      assert Gate.check(opts) == {:locked, :store_unreadable}
    end
  end

  describe "the hourly check" do
    test "a running install stays licensed through each passing failure", ctx do
      licensed!(ctx, 20)
      {AgentStore, store_opts} = ctx.store

      unreadable =
        Keyword.put(ctx.opts, :store, {AgentStore, Keyword.put(store_opts, :fail_reads, true)})

      for opts <- [
            unreadable,
            Keyword.put(ctx.opts, :licence_dir, nil),
            Keyword.put(ctx.opts, :machine_id_path, Path.join(ctx.tmp_dir, "none")),
            chip_gone(ctx)
          ] do
        assert Gate.recheck(opts) == :licensed
      end

      assert Gate.status(ctx.name) == :licensed
      refute_received :locked
    end

    test "a term that ends locks it and calls on_lock", ctx do
      record = licensed!(ctx, 3)
      later = Keyword.put(ctx.opts, :now, DateTime.add(record.term_end, 1, :second))

      assert Gate.recheck(later) == {:locked, :term_ended}
      assert_received :locked
      assert Gate.status(ctx.name) == {:locked, :term_ended}
    end

    test "a locked install the hourly check finds licensed calls on_unlock", ctx do
      licensed!(ctx, 20)
      machine_id = File.read!(ctx.install.machine_id_path)
      File.rm!(ctx.install.machine_id_path)
      assert {:locked, :machine_id_missing} = Gate.check(ctx.opts)
      File.write!(ctx.install.machine_id_path, machine_id)

      assert Gate.recheck(ctx.opts) == :licensed
      assert_received :unlocked
    end

    test "a gate that booted locked checks again each tick, and unlocks", ctx do
      opts = Keyword.put(ctx.opts, :check_every, 50)
      pid = start_supervised!({Gate, opts})
      assert Gate.status(ctx.name) == {:locked, :no_licence}

      # The licence becomes readable after the boot, as after a store
      # outage; stored without going through the gate.
      bytes = licence(ctx.install)
      {:ok, terms} = Aker.LicenceFile.verify(bytes, verify_opts(ctx.install))
      {AgentStore, store_opts} = ctx.store

      {:ok, _record} =
        AgentStore.store(
          %{
            envelope: bytes,
            licence_id: terms.licence_id,
            serial: 1,
            term_end: terms.term_end,
            last_seen_at: DateTime.utc_now()
          },
          :admin,
          store_opts
        )

      assert_receive :unlocked, 2_000
      assert Gate.status(ctx.name) == :licensed
      assert Process.alive?(pid)
    end
  end

  # A licence folder whose key the TPM chip made, on a machine whose chip
  # tools are gone.
  defp chip_gone(ctx) do
    dir = Path.join(ctx.tmp_dir, "chip-licence")
    File.mkdir_p!(Path.join(dir, "tpm_key"))
    File.write!(Path.join(dir, "tpm_key/key.pub"), "made by a chip")
    File.write!(Path.join(dir, "tpm_key/key.priv"), "made by a chip")

    ctx.opts
    |> Keyword.put(:licence_dir, dir)
    |> Keyword.put(:tpm_options, tools: Path.join(ctx.tmp_dir, "no-tools"))
  end

  describe "renewal" do
    test "renewal outside the last 7 days makes no call", ctx do
      licensed!(ctx, 8)
      server = LicensingServer.start({:licence, licence(ctx.install)}, ctx.install.public_key)

      assert Gate.tick(ctx.opts) == :licensed
      assert LicensingServer.calls(server) == []
    end

    test "inside them, one call per tick", ctx do
      licensed!(ctx, 6)
      renewed = licence(ctx.install, fields: %{"serial" => 2, "term_end" => iso(in_days(36))})
      server = LicensingServer.start({:licence, renewed}, ctx.install.public_key)

      assert Gate.tick(ctx.opts) == :licensed
      assert [%{path: "/api/v1/renew", verdict: :ok}] = LicensingServer.calls(server)
      assert %{serial: 2} = Gate.current(ctx.opts)
    end

    test "a failing server gets one call per tick", ctx do
      licensed!(ctx, 3)
      server = LicensingServer.start(:down, ctx.install.public_key)

      assert Gate.tick(ctx.opts) == :licensed
      assert [_one_call] = LicensingServer.calls(server)
    end

    test "a refused renewal keeps the licence until its term ends", ctx do
      record = licensed!(ctx, 3)
      LicensingServer.start({:refuse, 402, "not_paid"}, ctx.install.public_key)

      assert Gate.tick(ctx.opts) == :licensed
      assert %{serial: 1} = Gate.current(ctx.opts)
      refute_received :locked

      later = Keyword.put(ctx.opts, :now, DateTime.add(record.term_end, 1, :second))
      assert Gate.tick(later) == {:locked, :term_ended}
      assert_received :locked
    end

    test "an install whose term ended unlocks when the next tick's renewal succeeds", ctx do
      record = licensed!(ctx, 3)
      ended = Keyword.put(ctx.opts, :now, DateTime.add(record.term_end, 1, :second))
      LicensingServer.start({:refuse, 402, "not_paid"}, ctx.install.public_key)
      assert Gate.tick(ended) == {:locked, :term_ended}
      assert_received :locked

      # Paid: the server now answers a licence for the next term.
      renewed =
        licence(ctx.install,
          now: DateTime.add(record.term_end, 1, :second),
          fields: %{"serial" => 2, "term_end" => iso(DateTime.add(record.term_end, 30, :day))}
        )

      LicensingServer.start({:licence, renewed}, ctx.install.public_key)

      assert Gate.tick(ended) == :licensed
      assert_received :unlocked
      assert %{serial: 2} = Gate.current(ctx.opts)
    end

    test "a server answer with a lower serial, or another install key, is refused", ctx do
      licensed!(ctx, 3, 5)
      other = install(Path.join(ctx.tmp_dir, "other"))

      for answer <- [
            licence(ctx.install, fields: %{"serial" => 4}),
            licence(other, fields: %{"serial" => 6})
          ] do
        LicensingServer.start({:licence, answer}, ctx.install.public_key)
        assert {:error, refusal} = Gate.renew(ctx.opts)
        assert refusal in [:older_serial, :wrong_install_key]
      end

      assert %{serial: 5} = Gate.current(ctx.opts)

      LicensingServer.start(
        {:licence, licence(ctx.install, fields: %{"serial" => 6})},
        ctx.install.public_key
      )

      assert {:ok, %{serial: 6}} = Gate.renew(ctx.opts)
    end
  end

  describe "activation and refresh" do
    test "activation stores the licence the server sends", ctx do
      {:locked, :no_licence} = Gate.check(ctx.opts)
      server = LicensingServer.start({:licence, licence(ctx.install)}, ctx.install.public_key)

      assert {:ok, %{serial: 1}} = Gate.activate(ctx.opts, " ABCD-EFGH-2345 ", :admin)
      assert Gate.status(ctx.name) == :licensed

      assert [%{path: "/api/v1/activate", verdict: :ok, body: body}] =
               LicensingServer.calls(server)

      sent = Jason.decode!(body)
      assert sent["code"] == "ABCD-EFGH-2345"

      assert {:ok, %{install_public_key: key}} =
               Request.verify(Jason.encode!(sent["request"]), product: product())

      assert key == ctx.install.public_key
    end

    test "a bad activation code makes no call", ctx do
      server = LicensingServer.start({:licence, licence(ctx.install)}, ctx.install.public_key)

      for code <- ["", "abc def", "code;drop", String.duplicate("A", 65), "ünïcode", nil] do
        assert Gate.activate(ctx.opts, code, :admin) == {:error, :bad_code}, inspect(code)
      end

      assert LicensingServer.calls(server) == []
      assert AgentStore.rows(ctx.store) == []
      assert {:ok, _record} = Gate.activate(ctx.opts, String.duplicate("A", 64), :admin)
    end

    test "a code the server refuses stores nothing, and the code stays a string", ctx do
      server =
        LicensingServer.start({:refuse, 403, "code_used_never_an_atom"}, ctx.install.public_key)

      assert Gate.activate(ctx.opts, "ABCD", :admin) ==
               {:error, {:refused, "code_used_never_an_atom"}}

      assert [_one_call] = LicensingServer.calls(server)
      assert AgentStore.rows(ctx.store) == []
    end

    test "refresh stores this term's licence with the current seats", ctx do
      licensed!(ctx, 20)
      fresh = licence(ctx.install, fields: %{"serial" => 2, "seats" => 30})
      server = LicensingServer.start({:licence, fresh}, ctx.install.public_key)

      assert {:ok, %{serial: 2, seats: 30}} = Gate.refresh(ctx.opts, :admin)
      assert [%{path: "/api/v1/refresh", verdict: :ok}] = LicensingServer.calls(server)
    end

    test "refresh passes the host's actor to the store", ctx do
      licensed!(ctx, 20)

      LicensingServer.start(
        {:licence, licence(ctx.install, fields: %{"serial" => 2})},
        ctx.install.public_key
      )

      assert Gate.refresh(ctx.opts, :stranger) == {:error, :forbidden}
      assert %{serial: 1} = Gate.current(ctx.opts)
    end

    test "a server under a path signs the path the server reads", ctx do
      licensed!(ctx, 20)

      opts =
        Keyword.put(
          ctx.opts,
          :server,
          LicensingServer.server(base_url: "https://licensing.test/udin/")
        )

      server =
        LicensingServer.start(
          {:licence, licence(ctx.install, fields: %{"serial" => 2})},
          ctx.install.public_key
        )

      assert {:ok, %{serial: 2}} = Gate.refresh(opts, :admin)
      assert [%{path: "/udin/api/v1/refresh", verdict: :ok}] = LicensingServer.calls(server)
    end

    test "a call signed by another install's key is refused by the server", ctx do
      licensed!(ctx, 20)
      other = install(Path.join(ctx.tmp_dir, "other"))
      server = LicensingServer.start({:licence, licence(ctx.install)}, other.public_key)

      assert Gate.refresh(ctx.opts, :admin) == {:error, {:refused, "unknown_install"}}
      assert [%{verdict: :unknown_install}] = LicensingServer.calls(server)
    end
  end

  describe "the client" do
    test "an answer over 64 KB is bad_answer", ctx do
      LicensingServer.start({:licence, String.duplicate("x", 70_000)}, ctx.install.public_key)
      assert Gate.activate(ctx.opts, "ABCD", :admin) == {:error, :bad_answer}

      LicensingServer.start({:licence, licence(ctx.install)}, ctx.install.public_key)
      assert {:ok, _record} = Gate.activate(ctx.opts, "ABCD", :admin)
    end

    test "a redirect is not followed", ctx do
      server =
        LicensingServer.start(
          {:raw, 302, [{"location", "https://licensing.test/elsewhere"}], ""},
          ctx.install.public_key
        )

      assert Gate.activate(ctx.opts, "ABCD", :admin) == {:error, {:refused, "http_302"}}
      assert [%{path: "/api/v1/activate"}] = LicensingServer.calls(server)
    end

    test "a refusal code stays a string, cut to 64 characters", ctx do
      code = "unknown_code_" <> String.duplicate("z", 100)
      LicensingServer.start({:refuse, 403, code}, ctx.install.public_key)

      assert {:error, {:refused, refused}} = Gate.activate(ctx.opts, "ABCD", :admin)
      assert refused == String.slice(code, 0, 64)
    end

    test "an http base URL is refused, and makes no call", ctx do
      server = LicensingServer.start({:licence, licence(ctx.install)}, ctx.install.public_key)

      http =
        Keyword.put(ctx.opts, :server, LicensingServer.server(base_url: "http://licensing.test"))

      assert Gate.activate(http, "ABCD", :admin) == {:error, :insecure_url}
      assert LicensingServer.calls(server) == []

      allowed =
        Keyword.put(
          ctx.opts,
          :server,
          LicensingServer.server(base_url: "http://licensing.test", allow_http: true)
        )

      assert {:ok, _record} = Gate.activate(allowed, "ABCD", :admin)
    end

    test "with no server set, nothing is called and the log names the setting", ctx do
      opts =
        ctx.opts
        |> Keyword.put(:server, [])
        |> Keyword.put(:settings, server_url: "ACME_LICENSING_URL")

      log =
        capture_log(fn ->
          assert Gate.activate(opts, "ABCD", :admin) == {:error, :no_licensing_url}
        end)

      assert log =~ "Set ACME_LICENSING_URL."
    end
  end

  test "the gate's options are checked, and a bad one raises", ctx do
    assert_raise NimbleOptions.ValidationError, fn ->
      Gate.check(Keyword.delete(ctx.opts, :root_keys))
    end

    assert_raise NimbleOptions.ValidationError, fn ->
      Gate.check(Keyword.put(ctx.opts, :root_keys, "not a list"))
    end

    assert Gate.check(Keyword.put(ctx.opts, :root_keys, [])) == {:locked, :no_licence}
    _ = new_key()
  end
end
