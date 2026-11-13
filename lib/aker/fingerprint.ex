defmodule Aker.Fingerprint do
  @moduledoc """
  A fingerprint of the code an install runs, for the app to report with
  each renewal and refresh, so a licensing server can spot code that
  differs from the build it shipped.

  `release/2` hashes the release on disk: every file under `lib/*/ebin/`,
  the native libraries under `lib/*/priv/lib/` (where `crypto.so` checks
  the licence's signature) and at the top of each `lib/*/priv/`,
  `erts-*/bin/`, every version folder under `releases/` (the start script
  boots whichever one `RELEASE_VSN` names), and `bin/`. A symlink there
  counts by its target's name. It leaves out `releases/COOKIE`, the rest of
  each `priv/` (an app's data can run to gigabytes), `tmp/` and `log/`, and
  any folder inside a `priv/` the app lists in `:exclude`.

  `loaded/1` hashes the licensing code as it sits in memory: every aker
  module, plus the modules the app lists. `loaded_in_release/2` takes the
  same hash from a release's files, so a build can record the value a
  running install sends.

  This is evidence, not a lock: a patch that also fakes these answers still
  renews, and code loaded from outside the release (an `-pa` in
  `ERL_FLAGS`) shows only in `loaded/1`, and only for the modules it hashes. The module uses only the standard library, so a script can load
  it from a release's `ebin` without starting the app.
  """

  @hashed [
    "lib/*/ebin/**",
    "lib/*/priv/lib/**",
    "lib/*/priv/*.{so,dylib,dll}",
    "erts-*/bin/**",
    "releases/**",
    "bin/**"
  ]

  @doc """
  The lowercase hex SHA-256 of the lines `<relative path>\\0<file
  sha256>\\n` for the release under `root`, or `:not_a_release` when `root`
  holds no `releases/start_erl.data` naming a version folder.

  `root` defaults to `RELEASE_ROOT`, which a release's start script sets.
  Outside a release (dev, test) it is unset, and the answer is
  `:not_a_release`.

  Options: `:exclude`, folders inside an app's `priv/` to leave out, as
  wildcards such as `"lib/my_app-*/priv/lib/models"`. List only folders
  that hold data, never code: whatever sits there goes unseen. Write the
  list in the app's code, never in a setting a site can change. A pattern
  that matches anything outside a `priv/` folder raises `ArgumentError`.
  """
  @spec release(Path.t() | nil, keyword()) :: String.t() | :not_a_release
  def release(root \\ System.get_env("RELEASE_ROOT"), opts \\ [])
  def release(nil, _opts), do: :not_a_release

  def release(root, opts) do
    if release?(root) do
      root
      |> files(Keyword.get(opts, :exclude, []))
      |> Enum.map(fn relative -> [relative, 0, entry_hash(Path.join(root, relative)), ?\n] end)
      |> hex()
    else
      :not_a_release
    end
  end

  # `start_erl.data` holds "<erts version> <release version>": the version
  # the start scripts boot unless told otherwise.
  defp release?(root) do
    with {:ok, data} <- File.read(Path.join([root, "releases", "start_erl.data"])),
         [_erts, vsn] <- String.split(data) do
      File.dir?(Path.join([root, "releases", vsn]))
    else
      _other -> false
    end
  end

  # Each folder's listing comes back sorted, and the folders are in a fixed
  # order, so the lines are the same whatever order files were written in.
  defp files(root, exclude) do
    skipped =
      exclude
      |> Enum.flat_map(&Path.wildcard(Path.join(root, &1), match_dot: true))
      |> Enum.map(&(Path.relative_to(&1, root) <> "/"))
      |> Enum.map(&inside_priv!/1)

    @hashed
    |> Enum.flat_map(&Path.wildcard(Path.join(root, &1), match_dot: true))
    |> Enum.filter(&hashable?/1)
    |> Enum.map(&Path.relative_to(&1, root))
    |> Enum.uniq()
    |> Enum.sort()
    |> Enum.reject(fn relative ->
      relative == "releases/COOKIE" or Enum.any?(skipped, &String.starts_with?(relative, &1))
    end)
  end

  # Only data folders inside an app's priv/ may go unhashed.
  defp inside_priv!(relative) do
    if Regex.match?(~r{\Alib/[^/]+/priv/[^/]+.*/\z}, relative),
      do: relative,
      else: raise(ArgumentError, "exclude: takes only folders inside an app's priv/")
  end

  defp hashable?(path) do
    case File.lstat(path) do
      {:ok, %File.Stat{type: type}} -> type in [:regular, :symlink]
      _other -> false
    end
  end

  # A symlink counts by where it points, so swapping one for a link to
  # other code changes the hash, and a link that points elsewhere does too.
  defp entry_hash(path) do
    case File.read_link(path) do
      {:ok, target} -> "link:" <> target
      {:error, _not_a_link} -> file_hash(path)
    end
  end

  defp file_hash(path) do
    path
    |> File.stream!(65_536)
    |> Enum.reduce(:crypto.hash_init(:sha256), &:crypto.hash_update(&2, &1))
    |> :crypto.hash_final()
    |> Base.encode16(case: :lower)
  end

  @doc """
  `release/2`, taken once per `name` and kept for the life of the VM.
  Options: `:root` (default `RELEASE_ROOT`) and `:exclude`, as
  `release/2` takes them. Each app passes its own `name`.
  """
  @spec cached_release(atom(), keyword()) :: String.t() | :not_a_release
  def cached_release(name, opts \\ []) when is_atom(name) do
    key = {__MODULE__, :release, name}

    case :persistent_term.get(key, nil) do
      nil ->
        value =
          release(Keyword.get_lazy(opts, :root, fn -> System.get_env("RELEASE_ROOT") end), opts)

        :persistent_term.put(key, value)
        value

      value ->
        value
    end
  end

  @doc """
  The lowercase hex SHA-256 over the sorted `{module, md5}` of every aker
  module and the app's `:modules`, each md5 as the loaded code reports it.
  A module that cannot be loaded counts as `not_loaded`.
  """
  @spec loaded(keyword()) :: String.t()
  def loaded(opts) do
    (aker_modules() ++ Keyword.fetch!(opts, :modules))
    |> hash_modules(&loaded_md5/1)
  end

  @doc """
  `loaded/1`'s hash, read from the files of the release under `root`: aker's
  module list from its `.app` file, and the md5 each `.beam` file records,
  which is the md5 the loaded module reports. Takes `:modules` as
  `loaded/1` does.
  """
  @spec loaded_in_release(Path.t(), keyword()) :: String.t()
  def loaded_in_release(root, opts) do
    (release_aker_modules(root) ++ Keyword.fetch!(opts, :modules))
    |> hash_modules(&beam_md5(root, &1))
  end

  defp aker_modules, do: Application.spec(:aker, :modules) || []

  defp release_aker_modules(root) do
    with [path] <- Path.wildcard(Path.join([root, "lib", "aker-*", "ebin", "aker.app"])),
         {:ok, [{:application, :aker, spec}]} <- :file.consult(String.to_charlist(path)) do
      Keyword.get(spec, :modules, [])
    else
      _other -> []
    end
  end

  defp hash_modules(modules, md5) do
    modules
    |> Enum.uniq()
    |> Enum.sort()
    |> Enum.map(fn module -> [Atom.to_string(module), 0, md5.(module), ?\n] end)
    |> hex()
  end

  defp loaded_md5(module) do
    case Code.ensure_loaded(module) do
      {:module, _} -> Base.encode16(module.module_info(:md5), case: :lower)
      {:error, _why} -> "not_loaded"
    end
  end

  defp beam_md5(root, module) do
    with [beam] <- Path.wildcard(Path.join([root, "lib", "*", "ebin", "#{module}.beam"])),
         {:ok, {^module, md5}} <- :beam_lib.md5(String.to_charlist(beam)) do
      Base.encode16(md5, case: :lower)
    else
      _other -> "not_loaded"
    end
  end

  defp hex(iodata), do: :crypto.hash(:sha256, iodata) |> Base.encode16(case: :lower)
end
