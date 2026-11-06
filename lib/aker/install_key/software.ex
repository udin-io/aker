defmodule Aker.InstallKey.Software do
  @moduledoc """
  The install key as a PEM file, `install_key.pem`, in the licence folder,
  for a machine with no TPM chip.

  The file is made once, mode 0600 before any key byte is written, under a
  temporary name, synced to disk, and only then linked into place, so a
  crash mid-write never leaves a half key there. A copied disk carries
  this file, so on such a
  machine the host's machine id is what binds the licence.

  The private key is read for each signature and never kept in a process,
  and no error carries the file's contents.

  The file is staged in a fresh folder that is closed to other users
  before the file exists. Erlang cannot set the umask, so the folder is
  open for the moment between its creation and its chmod; a local user who
  enters it then could open the file in its own moment before its chmod.
  Both moments must line up, and a licence folder closed to other users
  (the library makes it 0700) leaves no such moment.
  """

  @behaviour Aker.InstallKey

  @file_name "install_key.pem"

  # SEC 1's ECPrivateKey for P-256 with its curve and public key (RFC
  # 5915): 121 DER bytes, fixed but for the two keys.
  @der_head <<0x30, 0x77, 0x02, 0x01, 0x01, 0x04, 0x20>>
  @der_middle <<0xA0, 0x0A, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07, 0xA1,
                0x44, 0x03, 0x42, 0x00>>
  # The order of P-256's base point (FIPS 186-4, D.1.2.3).
  @order 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
  @pem ~r/\A-----BEGIN EC PRIVATE KEY-----\r?\n([A-Za-z0-9+\/=\r\n]{1,300})-----END EC PRIVATE KEY-----\r?\n?\z/

  @impl true
  def kind, do: :software

  @impl true
  def ensure(opts) do
    path = path(opts)

    case public_key(opts) do
      {:error, :install_key_missing} -> make(path)
      answer -> answer
    end
  end

  @impl true
  def public_key(opts) do
    with {:ok, key} <- read(path(opts)), do: {:ok, public_half(key)}
  end

  @impl true
  def sign(message, opts) when is_binary(message) do
    with {:ok, key} <- read(path(opts)),
         do: {:ok, :crypto.sign(:ecdsa, :sha256, message, [key.private, :secp256r1])}
  end

  @doc "The key file's path for `opts`."
  @spec path(keyword()) :: Path.t()
  def path(opts), do: Path.join(Keyword.fetch!(opts, :dir), @file_name)

  defp read(path) do
    case File.read(path) do
      {:ok, text} -> decode(text)
      {:error, reason} when reason in [:enoent, :enotdir] -> {:error, :install_key_missing}
      {:error, _reason} -> {:error, :install_key_unreadable}
    end
  end

  # The file's fixed bytes are matched rather than handed to an ASN.1
  # decoder, which raises on a malformed file. The public key is
  # recomputed from the private one, so an edited file never passes.
  defp decode(text) do
    with [_all, body] <- Regex.run(@pem, text),
         {:ok, <<@der_head, private::binary-size(32), @der_middle, public::binary-size(65)>>} <-
           body |> String.replace(["\r", "\n"], "") |> Base.decode64(),
         true <- scalar?(private),
         {^public, _private} <- :crypto.generate_key(:ecdh, :secp256r1, private) do
      {:ok, %{private: private, public: public}}
    else
      _not_a_key -> {:error, :install_key_unreadable}
    end
  end

  # A private key is a number from 1 to the curve's order less one;
  # `:crypto` raises on any other.
  defp scalar?(private), do: :binary.decode_unsigned(private) in 1..(@order - 1)//1

  defp encode(%{private: private, public: public}) do
    der = <<@der_head, private::binary, @der_middle, public::binary>>
    "-----BEGIN EC PRIVATE KEY-----\n" <> Base.encode64(der) <> "\n-----END EC PRIVATE KEY-----\n"
  end

  defp public_half(%{public: public}), do: public

  defp make(path) do
    dir = Path.dirname(path)
    # Staged in a fresh folder closed to other users before the file
    # exists, so nobody can open the file while its mode is still loose.
    stage = Path.join(dir, ".key-" <> Base.url_encode64(:crypto.strong_rand_bytes(12)))
    temp = Path.join(stage, "install_key.pem")
    {public, private} = :crypto.generate_key(:ecdh, :secp256r1)
    # `:crypto` drops leading zero bytes; SEC 1 stores 32.
    key = %{private: pad(private), public: public}
    pem = encode(key)

    # Hard-linked into place, never renamed: a link fails when the file
    # exists, so of two first boots one keeps its key and the other reads
    # it, and both answer the key on disk.
    with :ok <- make_dir(dir),
         :ok <- File.mkdir(stage),
         :ok <- File.chmod(stage, 0o700),
         {:ok, file} <- File.open(temp, [:write, :exclusive, :binary]),
         :ok <- File.chmod(temp, 0o600),
         :ok <- IO.binwrite(file, pem),
         :ok <- :file.sync(file),
         :ok <- File.close(file) do
      link(stage, temp, path, key)
    else
      {:error, _reason} ->
        _ = File.rm_rf(stage)
        {:error, :install_key_unwritable}
    end
  end

  defp link(stage, temp, path, key) do
    linked = File.ln(temp, path)
    _ = File.rm_rf(stage)

    case linked do
      :ok -> {:ok, public_half(key)}
      {:error, :eexist} -> with({:ok, key} <- read(path), do: {:ok, public_half(key)})
      {:error, _reason} -> {:error, :install_key_unwritable}
    end
  end

  # A folder the library makes is closed to other users. One the operator
  # made keeps its mode: the app may write it without owning it.
  defp make_dir(dir) do
    if File.dir?(dir) do
      :ok
    else
      with :ok <- File.mkdir_p(dir), do: File.chmod(dir, 0o700)
    end
  end

  defp pad(private) when byte_size(private) < 32,
    do: :binary.copy(<<0>>, 32 - byte_size(private)) <> private

  defp pad(private), do: private
end
