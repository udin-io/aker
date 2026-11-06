defmodule Aker.InstallKey do
  @moduledoc """
  The keypair that ties a licence to one install. The licensing server
  stores its public half and names it in the signed licence; the app proves
  it holds the private half by signing a fresh random value.

  The key is ECDSA on NIST P-256, because TPM 2.0 chips sign on that curve
  and few sign Ed25519. A public key travels as the 65-byte uncompressed
  point, base64; a signature as DER, the form OpenSSL and the TPM tools
  write.

  `Aker.InstallKey.Software` keeps the private key in a file;
  `Aker.InstallKey.Tpm` keeps it in the chip.
  """

  alias Aker.InstallKey.{Software, Tpm}

  @typedoc "The uncompressed P-256 point: 0x04, then X and Y."
  @type public_key :: <<_::520>>

  @typedoc "Where the implementation keeps its key, such as `dir:`."
  @type opts :: keyword()

  @doc "Which kind of key this is, as an activation request names it."
  @callback kind() :: :software | :tpm

  @doc "Makes the key when there is none, and answers its public half."
  @callback ensure(opts()) :: {:ok, public_key()} | {:error, atom()}

  @doc "The public half of the key that exists, without making one."
  @callback public_key(opts()) :: {:ok, public_key()} | {:error, atom()}

  @doc "The DER ECDSA SHA-256 signature of `message`."
  @callback sign(message :: binary(), opts()) :: {:ok, binary()} | {:error, atom()}

  @doc """
  The install key for the licence folder `dir`, as `{module, opts}`.

  The key stays the kind that made it, since the licence names that key:
  a key made in the chip stays the chip's, so a machine whose chip is gone
  refuses rather than making a new key, and a key made in a file is never
  moved into a chip that appears later. A new install uses the chip when
  the machine has one, and a file otherwise.

  Options:

    * `:tpm_device` - the chip's device (default `/dev/tpmrm0`);
    * `:tpm_options` - options passed to `Aker.InstallKey.Tpm`.
  """
  @spec for_dir(Path.t(), keyword()) :: {module(), opts()}
  def for_dir(dir, opts \\ []) do
    device = Keyword.get(opts, :tpm_device, "/dev/tpmrm0")
    # The tools talk to the same device the choice read.
    options = Keyword.merge([tcti: "device:" <> device], Keyword.get(opts, :tpm_options, []))
    tpm = {Tpm, [dir: dir] ++ options}

    cond do
      Tpm.made_here?(dir) -> tpm
      File.exists?(Software.path(dir: dir)) -> {Software, dir: dir}
      File.exists?(device) -> tpm
      true -> {Software, dir: dir}
    end
  end

  @doc "Whether `signature` is `public_key`'s DER signature of `message`."
  @spec verify(binary(), binary(), binary()) :: boolean()
  def verify(<<4, _::512>> = public_key, message, signature)
      when is_binary(message) and is_binary(signature) and byte_size(signature) <= 80 do
    # `:crypto` raises on a point off the curve, and the point can come
    # from an untrusted request.
    point?(public_key) and
      :crypto.verify(:ecdsa, :sha256, message, signature, [public_key, :secp256r1])
  end

  def verify(_public_key, _message, _signature), do: false

  # P-256's field prime and curve constant b (FIPS 186-4, D.1.2.3); a is -3.
  @p 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
  @b 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B

  @doc "Whether `public_key` is an uncompressed point on P-256."
  @spec point?(binary()) :: boolean()
  def point?(<<4, x::256, y::256>>) when x < @p and y < @p do
    Integer.mod(y * y - (x * x * x - 3 * x + @b), @p) == 0
  end

  def point?(_public_key), do: false

  @doc """
  Signs a fresh 32-byte random value with the key `{module, opts}` names
  and checks the signature against `public_key`. True only when the key
  in hand is the one `public_key` describes.
  """
  @spec proves?({module(), opts()}, binary()) :: boolean()
  def proves?({module, opts}, public_key) do
    challenge = :crypto.strong_rand_bytes(32)

    case module.sign(challenge, opts) do
      {:ok, signature} -> verify(public_key, challenge, signature)
      {:error, _reason} -> false
    end
  end
end
