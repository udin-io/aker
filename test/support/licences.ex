defmodule ExLicence.TestSupport.Licences do
  @moduledoc """
  Licences for tests, signed the way `ExLicence.Issuer` signs them, for an
  install whose key and machine id sit in a test's own folder. The root key
  is made once per test run; no key file is checked in.
  """

  import ExLicence.TestSupport.Keys, only: [new_key: 0]

  alias ExLicence.Issuer
  alias ExLicence.SigningKey

  @product "acme_vision"

  @doc "The product every test licence names."
  def product, do: @product

  @doc "The root key this run's tests trust, made on first use."
  def root_key do
    case :persistent_term.get({__MODULE__, :root_key}, nil) do
      nil ->
        key = new_key()
        :persistent_term.put({__MODULE__, :root_key}, key)
        key

      key ->
        key
    end
  end

  @doc "The root key's public half, raw, as `:root_keys` takes it."
  def root_public_key, do: Base.decode64!(SigningKey.public_key(root_key()))

  @doc """
  A licence file for `install`, valid from an hour ago for 30 days.

  Options: `:fields` (string keys that replace the licence's), `:root_key`,
  `:working_key`, `:signing_key` (signs the licence; default the working
  key), `:key_id`, `:not_before`, `:not_after` and `:now`.
  """
  def licence(install, opts \\ []) do
    now = Keyword.get_lazy(opts, :now, &DateTime.utc_now/0) |> DateTime.truncate(:second)
    working_key = Keyword.get_lazy(opts, :working_key, &new_key/0)
    key_id = Keyword.get(opts, :key_id, "test-1")

    fields =
      Map.merge(
        %{
          "licence_id" => Issuer.uuid(),
          "serial" => 1,
          "product" => @product,
          "customer_name" => "Acme Logistics",
          "install_public_key" => Base.encode64(install.public_key),
          "machine_id_hash" => install.machine_id_hash,
          "term_start" => iso(DateTime.add(now, -1, :hour)),
          "term_end" => iso(DateTime.add(now, 30, :day)),
          "seats" => 10,
          "moves_per_term" => 20,
          "issued_at" => iso(DateTime.add(now, -1, :hour)),
          "working_key_id" => key_id
        },
        Keyword.get(opts, :fields, %{})
      )

    certificate =
      Issuer.certificate(Keyword.get_lazy(opts, :root_key, &root_key/0), working_key,
        key_id: key_id,
        not_before: Keyword.get(opts, :not_before, DateTime.add(now, -1, :day)),
        not_after: Keyword.get(opts, :not_after, DateTime.add(now, 365, :day))
      )

    Issuer.sign(fields, Keyword.get(opts, :signing_key, working_key), certificate)
  end

  @doc "The options `ExLicence.LicenceFile.verify/2` takes for `install`."
  def verify_opts(install, extra \\ []) do
    Keyword.merge(
      [
        product: @product,
        root_keys: [root_public_key()],
        install_key: install.install_key,
        machine_id_hash: install.machine_id_hash
      ],
      extra
    )
  end

  defp iso(time), do: DateTime.to_iso8601(time)
end

defmodule ExLicence.TestSupport.Licences.CopiedKey do
  @moduledoc """
  An install key that shows one public key and signs with another: what a
  copied install holds when it kept the licence and its public key but not
  the private key.
  """
  @behaviour ExLicence.InstallKey

  @impl true
  def kind, do: :software

  @impl true
  def ensure(opts), do: public_key(opts)

  @impl true
  def public_key(opts), do: {:ok, Keyword.fetch!(opts, :public_key)}

  @impl true
  def sign(message, opts) do
    {module, signer_opts} = Keyword.fetch!(opts, :signer)
    module.sign(message, signer_opts)
  end
end
