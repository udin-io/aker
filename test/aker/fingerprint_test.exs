defmodule Aker.FingerprintTest do
  @moduledoc """
  An app reports a fingerprint of the code it runs with each renewal, so
  the licensing server can spot changed code: the release on disk, and the
  licensing code in memory.
  """
  # Not async: one test reloads an aker module, which every test reads.
  use ExUnit.Case, async: false

  alias Aker.Fingerprint

  @moduletag :tmp_dir

  # A release root as `mix release` lays it out, written in `order`.
  defp release_tree(dir, order \\ :forward) do
    files = [
      {"lib/my_app-0.1.0/ebin/Elixir.MyApp.Licensing.beam", "gate"},
      {"lib/my_app-0.1.0/ebin/my_app.app", "app"},
      {"releases/0.1.0/consolidated/Elixir.Enumerable.beam", "protocol"},
      {"lib/crypto-5.5/priv/lib/crypto.so", "verify"},
      {"lib/aker-0.4.0/ebin/Elixir.Aker.Gate.beam", "aker gate"},
      {"lib/my_app-0.1.0/priv/big.bin", "not hashed"},
      {"releases/0.1.0/env.sh", "env"},
      {"releases/0.1.0/sys.config", "[]."},
      {"releases/0.1.0/start.boot", "boot"},
      {"releases/start_erl.data", "15.2 0.1.0"},
      {"releases/COOKIE", "cookie"},
      {"bin/my_app", "#!/bin/sh"},
      {"bin/server", "#!/bin/sh"},
      {"erts-15.2/bin/beam.smp", "vm"}
    ]

    files = if order == :reverse, do: Enum.reverse(files), else: files

    for {path, body} <- files do
      full = Path.join(dir, path)
      File.mkdir_p!(Path.dirname(full))
      File.write!(full, body)
    end

    dir
  end

  defp edit(root, path, body) do
    full = Path.join(root, path)
    File.mkdir_p!(Path.dirname(full))
    File.write!(full, body)
  end

  describe "release" do
    test "is lowercase hex, and the same whatever order the files were written in",
         %{tmp_dir: dir} do
      a = release_tree(Path.join(dir, "a"))
      b = release_tree(Path.join(dir, "b"), :reverse)

      assert Fingerprint.release(a) =~ ~r/\A[0-9a-f]{64}\z/
      assert Fingerprint.release(a) == Fingerprint.release(b)
    end

    for path <- [
          "lib/my_app-0.1.0/ebin/Elixir.MyApp.Licensing.beam",
          "lib/aker-0.4.0/ebin/Elixir.Aker.Gate.beam",
          "releases/0.1.0/consolidated/Elixir.Enumerable.beam",
          "lib/crypto-5.5/priv/lib/crypto.so",
          "erts-15.2/bin/beam.smp",
          "releases/0.1.0/env.sh",
          "releases/0.1.0/sys.config",
          "bin/my_app"
        ] do
      test "release hashes ebin, erts and releases: one byte of #{path} changes it",
           %{tmp_dir: dir} do
        root = release_tree(dir)
        before = Fingerprint.release(root)
        edit(root, unquote(path), File.read!(Path.join(root, unquote(path))) <> "x")

        refute Fingerprint.release(root) == before
      end
    end

    test "changes when a file is added to ebin or renamed there", %{tmp_dir: dir} do
      root = release_tree(dir)
      before = Fingerprint.release(root)
      edit(root, "lib/my_app-0.1.0/ebin/Elixir.Patched.beam", "patch")
      refute Fingerprint.release(root) == before

      File.rm!(Path.join(root, "lib/my_app-0.1.0/ebin/Elixir.Patched.beam"))
      assert Fingerprint.release(root) == before

      File.rename!(
        Path.join(root, "lib/my_app-0.1.0/ebin/my_app.app"),
        Path.join(root, "lib/my_app-0.1.0/ebin/my_app2.app")
      )

      refute Fingerprint.release(root) == before
    end

    test "changes when another version folder sits beside the one start_erl.data names",
         %{tmp_dir: dir} do
      root = release_tree(dir)
      before = Fingerprint.release(root)

      # The start script boots whichever folder RELEASE_VSN names.
      edit(root, "releases/0.1.0x/start.boot", "patched boot")

      refute Fingerprint.release(root) == before
    end

    test "release skips COOKIE, priv, tmp and log", %{tmp_dir: dir} do
      root = release_tree(dir)
      before = Fingerprint.release(root)

      edit(root, "lib/my_app-0.1.0/priv/big.bin", "changed")
      edit(root, "releases/COOKIE", "another cookie")
      edit(root, "tmp/my_app.runtime.sys.config", "[]")
      edit(root, "log/erlang.log.1", "boot")

      assert Fingerprint.release(root) == before
    end

    test "skips the folders an app lists in exclude:, and only those", %{tmp_dir: dir} do
      root = release_tree(dir)
      edit(root, "lib/my_app-0.1.0/priv/lib/models/big.so", "model")
      opts = [exclude: ["lib/my_app-*/priv/lib/models"]]
      before = Fingerprint.release(root, opts)

      edit(root, "lib/my_app-0.1.0/priv/lib/models/big.so", "another model")
      assert Fingerprint.release(root, opts) == before

      edit(root, "lib/my_app-0.1.0/ebin/Elixir.MyApp.Licensing.beam", "patched")
      refute Fingerprint.release(root, opts) == before
    end

    test "a symlink in a hashed folder changes it, and so does its target", %{tmp_dir: dir} do
      root = release_tree(dir)
      before = Fingerprint.release(root)
      elsewhere = Path.join(dir, "elsewhere.beam")
      File.write!(elsewhere, "patched")
      link = Path.join(root, "lib/my_app-0.1.0/ebin/Elixir.Aker.Gate.beam")
      File.ln_s!(elsewhere, link)
      linked = Fingerprint.release(root)
      refute linked == before

      File.rm!(link)
      File.ln_s!(Path.join(dir, "other.beam"), link)
      refute Fingerprint.release(root) == linked
    end

    test "a native library at the top of an app's priv/ changes it", %{tmp_dir: dir} do
      root = release_tree(dir)
      edit(root, "lib/my_app-0.1.0/priv/my_nif.so", "nif")
      before = Fingerprint.release(root)

      edit(root, "lib/my_app-0.1.0/priv/my_nif.so", "patched nif")
      refute Fingerprint.release(root) == before
    end

    test "exclude: takes only folders inside an app's priv/" do
      for pattern <- ["lib", "*", "**", "lib/*/ebin", "lib/my_app-*", "bin", "releases/0.1.0"] do
        assert_raise ArgumentError, fn ->
          Fingerprint.release(
            release_tree(
              Path.join(System.tmp_dir!(), "fp_#{System.unique_integer([:positive])}")
            ),
            exclude: [pattern]
          )
        end
      end
    end

    test "release answers :not_a_release without start_erl.data", %{tmp_dir: dir} do
      File.mkdir_p!(Path.join(dir, "lib/my_app/ebin"))
      assert Fingerprint.release(dir) == :not_a_release
      assert Fingerprint.release(nil) == :not_a_release
    end

    test "a start_erl.data naming no version folder is not a release", %{tmp_dir: dir} do
      root = release_tree(dir)
      edit(root, "releases/start_erl.data", "15.2 9.9.9")
      assert Fingerprint.release(root) == :not_a_release
    end

    test "the test build is not a release" do
      assert Fingerprint.release() == :not_a_release
    end

    test "cached_release keeps one value per caller's name", %{tmp_dir: dir} do
      root = release_tree(dir)
      name = :"fingerprint_test_#{System.unique_integer([:positive])}"
      first = Fingerprint.cached_release(name, root: root)
      assert first == Fingerprint.release(root)

      edit(root, "bin/my_app", "patched")
      assert Fingerprint.cached_release(name, root: root) == first
      refute Fingerprint.cached_release(:"#{name}_other", root: root) == first
    end
  end

  test "calls only Elixir and Erlang's own modules, so a script loads it alone" do
    {:ok, {_module, [imports: imports]}} =
      :beam_lib.chunks(:code.which(Fingerprint), [:imports])

    called = imports |> Enum.map(&elem(&1, 0)) |> Enum.uniq()

    standard =
      :erlang.pre_loaded() ++
        Enum.flat_map([:elixir, :kernel, :stdlib, :crypto], &Application.spec(&1, :modules))

    assert called -- standard == []
  end

  describe "loaded" do
    setup do
      name = :"Elixir.Aker.FingerprintThrowaway#{System.unique_integer([:positive])}"
      on_exit(fn -> :code.purge(name) && :code.delete(name) end)
      %{name: name}
    end

    defp compile!(name, body) do
      Code.compiler_options(ignore_module_conflict: true)

      Code.compile_string("""
      defmodule #{inspect(name)} do
        def answer, do: #{body}
      end
      """)
    after
      Code.compiler_options(ignore_module_conflict: false)
    end

    test "is lowercase hex, the same across calls and whatever the list's order",
         %{name: name} do
      compile!(name, ":licensed")

      assert Fingerprint.loaded(modules: [name]) =~ ~r/\A[0-9a-f]{64}\z/
      assert Fingerprint.loaded(modules: [name]) == Fingerprint.loaded(modules: [name])

      assert Fingerprint.loaded(modules: [name, String]) ==
               Fingerprint.loaded(modules: [String, name])
    end

    test "loaded changes when a listed module changes", %{name: name} do
      compile!(name, ":licensed")
      before = Fingerprint.loaded(modules: [name])

      compile!(name, ":always_licensed")

      refute Fingerprint.loaded(modules: [name]) == before
    end

    test "loaded changes when an aker module changes" do
      before = Fingerprint.loaded(modules: [])

      try do
        Code.compiler_options(ignore_module_conflict: true)

        Code.compile_string("""
        defmodule Aker.PublicKeys do
          def decode(_entries), do: {:ok, []}
        end
        """)

        refute Fingerprint.loaded(modules: []) == before
      after
        Code.compiler_options(ignore_module_conflict: false)
        :code.purge(Aker.PublicKeys)
        {:module, Aker.PublicKeys} = :code.load_file(Aker.PublicKeys)
      end

      assert Fingerprint.loaded(modules: []) == before
    end

    test "a module that cannot be loaded still counts" do
      missing = :"Elixir.Aker.NoSuchModule#{System.unique_integer([:positive])}"
      refute Fingerprint.loaded(modules: [missing]) == Fingerprint.loaded(modules: [])
    end

    test "loaded_in_release reads the same hash from a release's files", %{tmp_dir: dir} do
      # Stands in for an app's own module: a beam file outside aker's app.
      listed = [Jason]

      aker_ebin = Path.join(dir, "lib/aker-0.4.0/ebin")
      File.mkdir_p!(aker_ebin)
      from = Path.join(to_string(:code.lib_dir(:aker)), "ebin")
      File.cp!(Path.join(from, "aker.app"), Path.join(aker_ebin, "aker.app"))

      for beam <- Path.wildcard(Path.join(from, "*.beam")),
          do: File.cp!(beam, Path.join(aker_ebin, Path.basename(beam)))

      app_ebin = Path.join(dir, "lib/my_app-0.1.0/ebin")
      File.mkdir_p!(app_ebin)
      Code.ensure_loaded!(Jason)

      File.cp!(:code.which(Jason), Path.join(app_ebin, "Elixir.Jason.beam"))

      assert Fingerprint.loaded_in_release(dir, modules: listed) ==
               Fingerprint.loaded(modules: listed)

      # Aker.Gate compiled with another body, written over its beam, changes
      # the recorded value. Compiled to a binary only, so the VM keeps the real one.
      {:ok, Aker.Gate, patched} =
        :compile.forms(
          [
            {:attribute, 1, :module, Aker.Gate},
            {:attribute, 1, :export, [answer: 0]},
            {:function, 1, :answer, 0, [{:clause, 1, [], [], [{:atom, 1, :licensed}]}]}
          ],
          [:binary]
        )

      File.write!(Path.join(aker_ebin, "Elixir.Aker.Gate.beam"), patched)

      refute Fingerprint.loaded_in_release(dir, modules: listed) ==
               Fingerprint.loaded(modules: listed)
    end
  end
end
