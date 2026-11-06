defmodule ExLicence.Issuer do
  @moduledoc """
  Signs a licence file from an activation request. A licensing server
  calls it, and `mix ex_licence.sign` calls it on a developer's machine.

  It signs only with the keys its caller hands it, held as
  `ExLicence.SigningKey`. A host may ship it in every release, which is
  safe: a host trusts only the root public keys it passes, so nobody
  without a trusted root's private key makes a licence the host accepts.
  """

  alias ExLicence.LicenceFile
  alias ExLicence.Request
  alias ExLicence.SigningKey

  # A working key's certificate lasts at most 13 months.
  @certificate_days 395
  # A term of up to 100 years keeps every date a four-digit year.
  @max_term_days 36_500

  @doc """
  The licence file for `request_bytes`, a request for `opts[:product]`.

  Options: `:product`, `:root_key` and `:working_key`
  (`ExLicence.SigningKey`), `:customer`, `:seats`, `:term_days`, and
  optionally `:features` (`[]`), `:serial` (1), `:moves_per_term` (20),
  `:key_id` (`"dev"`) and `:now`.

  It signs only a licence `ExLicence.LicenceFile.verify/2` reads back, and
  answers `{:error, {:invalid, option}}` for the first option outside the
  reader's bounds, or `{:error, {:invalid, :size}}` when the licence would
  be over the reader's 4 KB.
  """
  @spec issue(binary(), keyword()) ::
          {:ok, binary()} | {:error, :bad_request | {:invalid, atom()}}
  def issue(request_bytes, opts) do
    product = Keyword.fetch!(opts, :product)
    now = opts |> Keyword.get_lazy(:now, &DateTime.utc_now/0) |> DateTime.truncate(:second)
    key_id = Keyword.get(opts, :key_id, "dev")

    with {:ok, request} <- Request.verify(request_bytes, product: product),
         :ok <- check_options(opts, key_id) do
      fields = %{
        "licence_id" => uuid(),
        "serial" => Keyword.get(opts, :serial, 1),
        "product" => product,
        "customer_name" => Keyword.fetch!(opts, :customer),
        "install_public_key" => Base.encode64(request.install_public_key),
        "machine_id_hash" => request.machine_id_hash,
        "term_start" => iso(now),
        "term_end" => iso(DateTime.add(now, Keyword.fetch!(opts, :term_days), :day)),
        "seats" => Keyword.fetch!(opts, :seats),
        "moves_per_term" => Keyword.get(opts, :moves_per_term, 20),
        "features" => Keyword.get(opts, :features, []),
        "issued_at" => iso(now),
        "working_key_id" => key_id
      }

      certificate =
        certificate(Keyword.fetch!(opts, :root_key), Keyword.fetch!(opts, :working_key),
          key_id: key_id,
          not_before: DateTime.add(now, -1, :day),
          not_after: DateTime.add(now, @certificate_days, :day)
        )

      if LicenceFile.licence_fits?(Jason.encode!(fields)),
        do: {:ok, sign(fields, Keyword.fetch!(opts, :working_key), certificate)},
        else: {:error, {:invalid, :size}}
    end
  end

  # The bounds `LicenceFile` reads a licence with, so nothing signed here
  # is refused there.
  defp check_options(opts, key_id) do
    [
      customer: text?(Keyword.fetch!(opts, :customer), 400),
      seats: count?(Keyword.fetch!(opts, :seats), 0),
      term_days: is_integer(opts[:term_days]) and opts[:term_days] in 1..@max_term_days,
      serial: count?(Keyword.get(opts, :serial, 1), 1),
      moves_per_term: count?(Keyword.get(opts, :moves_per_term, 20), 0),
      key_id: text?(key_id, 64),
      features: LicenceFile.features?(Keyword.get(opts, :features, []))
    ]
    |> Enum.find(fn {_option, ok?} -> not ok? end)
    |> case do
      nil -> :ok
      {option, false} -> {:error, {:invalid, option}}
    end
  end

  defp text?(value, max), do: is_binary(value) and byte_size(value) in 1..max
  defp count?(value, min), do: is_integer(value) and value >= min

  @doc """
  The working key's certificate, signed by the root key: its public key,
  `:key_id`, `:not_before` and `:not_after`.
  """
  @spec certificate(SigningKey.t(), SigningKey.t(), keyword()) :: %{
          certificate: binary(),
          certificate_signature: binary()
        }
  def certificate(root_key, working_key, opts) do
    bytes =
      Jason.encode!(%{
        "purpose" => LicenceFile.certificate_purpose(),
        "public_key" => SigningKey.public_key(working_key),
        "key_id" => Keyword.fetch!(opts, :key_id),
        "not_before" => iso(Keyword.fetch!(opts, :not_before)),
        "not_after" => iso(Keyword.fetch!(opts, :not_after))
      })

    %{certificate: bytes, certificate_signature: SigningKey.sign(root_key, bytes)}
  end

  @doc "The licence file for `fields`, signed by `working_key`, carrying `certificate`."
  @spec sign(map(), SigningKey.t(), map()) :: binary()
  def sign(fields, working_key, certificate) do
    licence = Jason.encode!(fields)

    LicenceFile.encode(%{
      licence: licence,
      signature: SigningKey.sign(working_key, licence),
      certificate: certificate.certificate,
      certificate_signature: certificate.certificate_signature
    })
  end

  @doc "A random UUID, version 4 (RFC 9562), as lowercase text."
  @spec uuid() :: String.t()
  def uuid do
    <<a::48, _version::4, b::12, _variant::2, c::62>> = :crypto.strong_rand_bytes(16)
    <<hex::binary-size(32)>> = Base.encode16(<<a::48, 4::4, b::12, 2::2, c::62>>, case: :lower)

    <<p1::binary-size(8), p2::binary-size(4), p3::binary-size(4), p4::binary-size(4),
      p5::binary-size(12)>> = hex

    Enum.join([p1, p2, p3, p4, p5], "-")
  end

  defp iso(time), do: time |> DateTime.truncate(:second) |> DateTime.to_iso8601()
end
