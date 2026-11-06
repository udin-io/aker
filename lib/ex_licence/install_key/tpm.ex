defmodule ExLicence.InstallKey.Tpm do
  @moduledoc """
  The install key inside the machine's TPM 2.0 chip. The chip
  makes the P-256 keypair and never lets the private half out, so a copied
  disk cannot prove it is the licensed machine.

  The library drives the chip through `tpm2-tools`, each call under `timeout`, so
  a chip that hangs costs a refusal, not a stuck boot. The licence folder
  keeps `key.pub` and `key.priv`, the key as the chip exported it:
  the private part is sealed by the chip's own storage key, so it is useless
  on any other chip. They sit in the folder `tpm_key`, which appears whole
  by one rename after both are synced to disk. Each call recreates the chip's primary key, which the
  chip derives from its own seed and so is the same every time, loads the
  key under it, does its work in a fresh temporary folder, and flushes
  what it loaded.

  `opts`:

    * `:dir`: the licence folder (required);
    * `:tcti`: how to reach the chip (default `device:/dev/tpmrm0`; the
      tests pass `swtpm:port=<n>`);
    * `:tools`: the folder holding the `tpm2_*` programs (default: the
      `PATH`);
    * `:timeout_s`: the limit on each call, 1 to 60 seconds (default 10).

  Every failure answers an atom and logs the tool's output; no output ever
  holds key material, since the chip never releases it.
  """

  @behaviour ExLicence.InstallKey

  require Logger

  # The key's folder inside the licence folder. It appears whole, by one
  # rename, so a crash or a second first boot never leaves half a key.
  @key_dir "tpm_key"
  @public "tpm_key/key.pub"
  @private "tpm_key/key.priv"
  @attributes "fixedtpm|fixedparent|sensitivedataorigin|userwithauth|sign"
  # SubjectPublicKeyInfo for a P-256 key (RFC 5480): 91 DER bytes, fixed but
  # for the point.
  @spki_head <<0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01, 0x06,
               0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00>>

  @impl true
  def kind, do: :tpm

  @doc "Whether the licence folder `dir` holds a key the chip made."
  @spec made_here?(Path.t()) :: boolean()
  def made_here?(dir), do: File.exists?(Path.join(Path.expand(dir), @public))

  @impl true
  def ensure(opts) do
    if made_here?(dir(opts)), do: public_key(opts), else: make(opts)
  end

  @impl true
  def public_key(opts) do
    in_key_scratch(opts, fn scratch ->
      with :ok <- load(opts, scratch),
           :ok <- run(opts, "tpm2_readpublic", ~w(-Q -c key.ctx -f der -o key.der), scratch),
           {:ok, <<@spki_head, point::binary-size(65)>>} <-
             read(Path.join(scratch, "key.der")) do
        {:ok, point}
      else
        {:ok, _other_shape} -> {:error, :install_key_unreadable}
        {:error, reason} -> {:error, reason}
      end
    end)
  end

  @impl true
  def sign(message, opts) when is_binary(message) do
    in_key_scratch(opts, fn scratch ->
      with :ok <- write(Path.join(scratch, "message"), message),
           :ok <- load(opts, scratch),
           :ok <-
             run(
               opts,
               "tpm2_sign",
               ~w(-Q -c key.ctx -g sha256 -f plain -o signature message),
               scratch
             ) do
        read(Path.join(scratch, "signature"))
      end
    end)
  end

  defp make(opts) do
    dir = dir(opts)

    in_scratch(opts, fn scratch ->
      staged = Path.join(scratch, "staged")

      with :ok <- primary(opts, scratch),
           :ok <-
             run(
               opts,
               "tpm2_create",
               ["-Q", "-C", "primary.ctx", "-G", "ecc256:ecdsa-sha256", "-a", @attributes] ++
                 ~w(-u key.pub -r key.priv),
               scratch
             ),
           :ok <- File.mkdir(staged),
           :ok <- copy_synced(Path.join(scratch, "key.pub"), Path.join(staged, "key.pub")),
           :ok <- copy_synced(Path.join(scratch, "key.priv"), Path.join(staged, "key.priv")) do
        place(staged, Path.join(dir, @key_dir), opts)
      else
        {:error, reason} when reason in [:install_key_missing, :install_key_timeout] ->
          {:error, reason}

        {:error, _reason} ->
          {:error, :install_key_unwritable}
      end
    end)
  end

  defp place(staged, key_dir, opts) do
    case File.rename(staged, key_dir) do
      :ok -> public_key(opts)
      # Another first boot placed its key first: answer that one.
      {:error, reason} when reason in [:eexist, :enotempty] -> public_key(opts)
      {:error, _reason} -> {:error, :install_key_unwritable}
    end
  end

  defp copy_synced(from, to) do
    with {:ok, bytes} <- File.read(from), do: write(to, bytes)
  end

  # Written and synced to disk before the folder holding it is renamed
  # into place.
  defp write(path, bytes) do
    with {:ok, file} <- File.open(path, [:write, :exclusive, :binary]),
         :ok <- IO.binwrite(file, bytes),
         :ok <- :file.sync(file) do
      File.close(file)
    else
      {:error, _reason} -> {:error, :install_key_unwritable}
    end
  end

  defp read(path) do
    case File.read(path) do
      {:ok, bytes} -> {:ok, bytes}
      {:error, _reason} -> {:error, :install_key_unreadable}
    end
  end

  defp load(opts, scratch) do
    dir = dir(opts)

    with true <- File.exists?(Path.join(dir, @public)) || {:error, :install_key_missing},
         :ok <- primary(opts, scratch) do
      run(
        opts,
        "tpm2_load",
        ["-Q", "-C", "primary.ctx", "-u", Path.join(dir, @public), "-r", Path.join(dir, @private)] ++
          ~w(-c key.ctx),
        scratch
      )
    end
  end

  defp primary(opts, scratch),
    do: run(opts, "tpm2_createprimary", ~w(-Q -C o -g sha256 -G ecc256 -c primary.ctx), scratch)

  # One tool call under `timeout`, then every transient object flushed:
  # without the kernel's resource manager the chip keeps them, and fills.
  defp run(opts, tool, args, scratch) do
    result = call(opts, tool, args, scratch)
    _ = call(opts, "tpm2_flushcontext", ["-t"], scratch)
    result
  end

  defp call(opts, tool, args, scratch) do
    executable = executable(opts, tool)

    case {executable, System.find_executable("timeout"), timeout_s(opts)} do
      {_executable, _timeout, :error} ->
        Logger.error(
          "licence: the TPM option :timeout_s is a whole number of seconds from 1 to 60"
        )

        {:error, :install_key_missing}

      {nil, _timeout, _limit} ->
        Logger.error("licence: #{tool} is not installed; the TPM install key needs tpm2-tools")
        {:error, :install_key_missing}

      {_executable, nil, _limit} ->
        Logger.error("licence: `timeout` is not installed; the TPM install key needs coreutils")
        {:error, :install_key_missing}

      {executable, timeout, limit} ->
        {output, status} =
          System.cmd(timeout, ["--kill-after=2", Integer.to_string(limit), executable | args],
            cd: scratch,
            env: [{"TPM2TOOLS_TCTI", Keyword.get(opts, :tcti, "device:/dev/tpmrm0")}],
            stderr_to_stdout: true
          )

        answer(tool, status, output)
    end
  end

  # The tools run in a scratch folder, so a relative licence folder would
  # name another place there.
  defp dir(opts), do: Path.expand(Keyword.fetch!(opts, :dir))

  # `timeout 0` means no limit at all, so only 1 to 60 seconds pass.
  defp timeout_s(opts) do
    case Keyword.get(opts, :timeout_s, 10) do
      seconds when is_integer(seconds) and seconds in 1..60 -> seconds
      _other -> :error
    end
  end

  defp answer(_tool, 0, _output), do: :ok

  defp answer(tool, status, output) when status in [124, 137] do
    Logger.error(
      "licence: #{tool} took too long and was stopped: #{String.slice(output, 0, 500)}"
    )

    {:error, :install_key_timeout}
  end

  defp answer(tool, status, output) do
    Logger.error("licence: #{tool} failed (exit #{status}): #{String.slice(output, 0, 500)}")
    {:error, :install_key_missing}
  end

  defp executable(opts, tool) do
    case Keyword.get(opts, :tools) do
      nil -> System.find_executable(tool)
      dir -> if File.regular?(Path.join(dir, tool)), do: Path.join(dir, tool)
    end
  end

  # A call on the key the chip made, or `:install_key_missing` when there
  # is none, without making a folder.
  defp in_key_scratch(opts, fun) do
    if made_here?(dir(opts)),
      do: in_scratch(opts, fun),
      else: {:error, :install_key_missing}
  end

  # A fresh folder per call inside the licence folder, made exclusively with
  # a random name and mode 0700, and removed after, so two calls never share
  # context files and no other user can plant one.
  defp in_scratch(opts, fun) do
    dir = dir(opts)
    scratch = Path.join(dir, ".tpm-" <> Base.url_encode64(:crypto.strong_rand_bytes(12)))

    with :ok <- make_dir(dir),
         :ok <- File.mkdir(scratch),
         :ok <- File.chmod(scratch, 0o700) do
      answer = fun.(scratch)
      File.rm_rf(scratch)
      answer
    else
      {:error, _reason} -> {:error, :install_key_unwritable}
    end
  end

  # A folder the library makes is closed to other users; one the operator
  # made keeps its mode, as `ExLicence.InstallKey.Software` does.
  defp make_dir(dir) do
    if File.dir?(dir), do: :ok, else: with(:ok <- File.mkdir_p(dir), do: File.chmod(dir, 0o700))
  end
end
