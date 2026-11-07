defmodule Aker.Request do
  @moduledoc """
  The activation request an install sends the licensing server to get its
  licence.

  One JSON object with two base64 fields: `request`, the request JSON
  bytes, and `signature`, the install key's DER signature of them. The
  signature proves the sender holds the private half of the key it names.
  The request names the product and its version, the install public key
  and its kind (software or TPM), the machine id hash, the time and a
  16-byte random nonce.
  """

  alias Aker.InstallKey

  @max_bytes 8 * 1024
  @product ~r/\A[a-z0-9_-]{1,64}\z/
  @hash ~r/\A[0-9a-f]{64}\z/

  @doc "The largest request `verify/2` reads, in bytes."
  @spec max_bytes() :: pos_integer()
  def max_bytes, do: @max_bytes

  @doc """
  Whether `name` is a product name: 1 to 64 characters of `a-z`, `0-9`,
  `_` and `-`.
  """
  @spec product?(term()) :: boolean()
  def product?(name), do: is_binary(name) and Regex.match?(@product, name)

  @doc """
  A new request for this install, as the file's bytes.

  Options:

    * `:product` - the product's name (required, see `product?/1`);
    * `:product_version` - the app's version, 1 to 64 characters of
      `0-9 A-Z a-z . + -` (required);
    * `:install_key` - `{module, opts}` (required);
    * `:machine_id_hash` - from `Aker.MachineId.hash/1`, 64 hex
      characters (required);
    * `:now` - the time the request names (default now).
  """
  @spec build(keyword()) :: {:ok, binary()} | {:error, atom()}
  def build(opts) do
    product = Keyword.fetch!(opts, :product)
    version = Keyword.fetch!(opts, :product_version)
    {module, key_opts} = Keyword.fetch!(opts, :install_key)
    now = Keyword.get_lazy(opts, :now, &DateTime.utc_now/0)

    with :ok <- check_product(product),
         :ok <- check(version?(version), :bad_product_version),
         :ok <- check(hash?(Keyword.fetch!(opts, :machine_id_hash)), :bad_machine_id_hash),
         {:ok, public_key} <- module.public_key(key_opts) do
      request =
        Jason.encode!(%{
          "product" => product,
          "product_version" => version,
          "install_public_key" => Base.encode64(public_key),
          "install_key_kind" => Atom.to_string(module.kind()),
          "machine_id_hash" => Keyword.fetch!(opts, :machine_id_hash),
          "created_at" => DateTime.to_iso8601(DateTime.truncate(now, :second)),
          "nonce" => Base.encode64(:crypto.strong_rand_bytes(16))
        })

      with {:ok, signature} <- module.sign(request, key_opts) do
        {:ok,
         Jason.encode!(%{
           "request" => Base.encode64(request),
           "signature" => Base.encode64(signature)
         })}
      end
    end
  end

  defp check_product(product), do: check(product?(product), :bad_product)

  defp check(true, _refusal), do: :ok
  defp check(false, refusal), do: {:error, refusal}

  # A version as Mix and SemVer spell one, so the request stays under the
  # size `verify/2` reads.
  defp version?(version),
    do: is_binary(version) and Regex.match?(~r/\A[0-9A-Za-z.+-]{1,64}\z/, version)

  defp hash?(hash), do: is_binary(hash) and Regex.match?(@hash, hash)

  @doc """
  The request's fields, when `bytes` is a request for the product
  `opts[:product]` signed by the key it names: `install_public_key`,
  `machine_id_hash`, `product_version`, `install_key_kind` (`:software`
  or `:tpm`), `created_at` (`DateTime`, UTC) and `nonce` (16 bytes). A
  licensing server records the version and kind, and checks the time and
  nonce against replays. The sign task reads a request through this.
  """
  @spec verify(binary(), keyword()) ::
          {:ok,
           %{
             install_public_key: binary(),
             machine_id_hash: String.t(),
             product_version: String.t(),
             install_key_kind: :software | :tpm,
             created_at: DateTime.t(),
             nonce: <<_::128>>
           }}
          | {:error, :bad_request}
  def verify(bytes, opts) when is_binary(bytes) and byte_size(bytes) <= @max_bytes do
    product = Keyword.fetch!(opts, :product)

    with true <- product?(product),
         {:ok, %{"request" => request, "signature" => signature}}
         when is_binary(request) and is_binary(signature) <-
           Jason.decode(bytes),
         {:ok, request} <- Base.decode64(request),
         {:ok, signature} <- Base.decode64(signature),
         {:ok,
          %{
            "product" => ^product,
            "product_version" => version,
            "install_public_key" => public_key,
            "install_key_kind" => kind,
            "machine_id_hash" => machine_id_hash,
            "created_at" => created_at,
            "nonce" => nonce
          }}
         when is_binary(public_key) and is_binary(machine_id_hash) and is_binary(created_at) and
                is_binary(nonce) <- Jason.decode(request),
         true <- hash?(machine_id_hash),
         true <- version?(version),
         {:ok, kind} <- key_kind(kind),
         {:ok, created_at, _offset} <- DateTime.from_iso8601(created_at),
         {:ok, <<_::128>> = nonce} <- Base.decode64(nonce),
         {:ok, <<4, _::512>> = public_key} <- Base.decode64(public_key),
         true <- InstallKey.verify(public_key, request, signature) do
      {:ok,
       %{
         install_public_key: public_key,
         machine_id_hash: machine_id_hash,
         product_version: version,
         install_key_kind: kind,
         created_at: created_at,
         nonce: nonce
       }}
    else
      _malformed -> {:error, :bad_request}
    end
  end

  def verify(_bytes, _opts), do: {:error, :bad_request}

  defp key_kind("software"), do: {:ok, :software}
  defp key_kind("tpm"), do: {:ok, :tpm}
  defp key_kind(_other), do: :error
end
