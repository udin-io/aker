defmodule ExLicence.SigningKey do
  @moduledoc """
  A private Ed25519 key: a licence issuer's root key, or a working key
  the root key certifies. Only a signing task reads one, from a file kept off the
  repository and off every server. `inspect/1` shows no key bytes, so a
  crash or a log line that holds the key prints none.

  `from_pem/1` takes what `openssl genpkey -algorithm ed25519` writes: one
  unencrypted PKCS #8 block. It matches the block's fixed bytes instead of
  calling a decoder, so a file that is not such a key gets one fixed error
  and no exception that could print the file.
  """

  @enforce_keys [:seed]
  defstruct [:seed]

  @opaque t :: %__MODULE__{seed: <<_::256>>}

  # PKCS #8 for Ed25519 (RFC 8410): a 48-byte DER sequence whose last 32
  # bytes are the private key.
  @der_prefix <<0x30, 0x2E, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x70, 0x04,
                0x22, 0x04, 0x20>>

  @pem ~r/\A-----BEGIN PRIVATE KEY-----\r?\n([A-Za-z0-9+\/=\r\n]{1,200})-----END PRIVATE KEY-----\r?\n?\z/

  @doc "The key in a PEM file's text, or `:error` when the text is not one."
  @spec from_pem(binary()) :: {:ok, t()} | :error
  def from_pem(text) when is_binary(text) do
    with [_all, body] <- Regex.run(@pem, text),
         {:ok, <<@der_prefix, seed::binary-size(32)>>} <-
           body |> String.replace(["\r", "\n"], "") |> Base.decode64() do
      {:ok, %__MODULE__{seed: seed}}
    else
      _not_a_key -> :error
    end
  end

  def from_pem(_text), do: :error

  @doc """
  The key in the file at `path`, refused when the file sits inside `repo`,
  the checkout a signing task runs in, so a key cannot be committed by
  accident. Each failure is one fixed message that prints nothing of the
  file.
  """
  @spec load(Path.t(), Path.t()) :: {:ok, t()} | {:error, String.t()}
  def load(path, repo) do
    # Compared after every symlink is followed, so a link outside the
    # checkout to a key inside it, or a key under a linked copy of the
    # checkout's path, is still inside. Case-folded, since macOS's disk
    # reads APP/ and app/ as one folder.
    with {:ok, real} <- real_path(path),
         {:ok, real_repo} <- real_path(repo),
         false <- inside?(String.downcase(real), String.downcase(real_repo)) do
      read(path)
    else
      true ->
        {:error,
         "the key is inside #{repo}; keep it off the repository and pass its path outside"}

      {:error, :too_many_links} ->
        {:error, "the key's path follows too many links"}
    end
  end

  defp inside?(path, dir), do: path == dir or String.starts_with?(path, dir <> "/")

  @doc """
  `path` absolute, with every symlink along it followed, as far as the
  links resolve. A part that does not exist is kept as written. Each `..`
  applies after the link before it is followed, as the system applies it.
  More than 40 links answers `{:error, :too_many_links}`.
  """
  @spec real_path(Path.t()) :: {:ok, Path.t()} | {:error, :too_many_links}
  def real_path(path), do: resolve(path |> Path.absname() |> Path.split(), [], 40)

  defp resolve([], done, _hops), do: {:ok, join(done)}
  defp resolve(["." | rest], done, hops), do: resolve(rest, done, hops)
  defp resolve([".." | rest], [_part, _root | _] = done, hops), do: resolve(rest, tl(done), hops)
  defp resolve([".." | rest], done, hops), do: resolve(rest, done, hops)

  defp resolve([part | rest], done, hops) do
    case File.read_link(join([part | done])) do
      {:ok, _target} when hops == 0 ->
        {:error, :too_many_links}

      {:ok, target} ->
        case Path.type(target) do
          :absolute -> resolve(Path.split(target) ++ rest, [], hops - 1)
          _relative -> resolve(Path.split(target) ++ rest, done, hops - 1)
        end

      {:error, _not_a_link} ->
        resolve(rest, [part | done], hops)
    end
  end

  defp join(done), do: done |> Enum.reverse() |> Path.join()

  defp read(path) do
    with {:ok, text} <- File.read(path),
         {:ok, key} <- from_pem(text) do
      {:ok, key}
    else
      {:error, reason} when is_atom(reason) ->
        {:error, "cannot read the key file: #{:file.format_error(reason)}"}

      :error ->
        {:error, "the key file is not an Ed25519 private key in PEM form"}
    end
  end

  @doc "The raw 32-byte public key, base64, as a host's root key list holds it."
  @spec public_key(t()) :: String.t()
  def public_key(%__MODULE__{seed: seed}) do
    {public, _private} = :crypto.generate_key(:eddsa, :ed25519, seed)
    Base.encode64(public)
  end

  @doc "The 64-byte Ed25519 signature of `message`."
  @spec sign(t(), binary()) :: binary()
  def sign(%__MODULE__{seed: seed}, message) when is_binary(message),
    do: :crypto.sign(:eddsa, :none, message, [seed, :ed25519])

  defimpl Inspect do
    def inspect(_key, _opts), do: "#ExLicence.SigningKey<redacted>"
  end
end
