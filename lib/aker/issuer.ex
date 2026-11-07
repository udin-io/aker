defmodule Aker.Issuer do
  @moduledoc """
  Signs a licence file from an activation request. A licensing server
  calls it, and `mix aker.sign` calls it on a developer's machine.

  It signs only with the keys its caller hands it, held as
  `Aker.SigningKey`. A host may ship it in every release, which is
  safe: a host trusts only the root public keys it passes, so nobody
  without a trusted root's private key makes a licence the host accepts.
  """

  alias Aker.LicenceFile
  alias Aker.Request
  alias Aker.SigningKey

  # A working key's certificate lasts at most 13 months.
  @certificate_days 395
  # A term of up to 100 years keeps every date a four-digit year.
  @max_term_days 36_500
  # `encode_certificate/1`'s line fits one secret.
  @max_encoded_bytes 2048

  @doc """
  The licence file for `request_bytes`, a request for `opts[:product]`.

  It signs with `:working_key` (`Aker.SigningKey`), under one of two
  certificates:

    * `:certificate` and `:root_keys`: a certificate `mix aker.certify`
      made offline, as `decode_certificate/1` reads it, and the root
      public keys (raw, 32 bytes) one of which must have signed it. A
      licensing server signs this way and never holds the root key. The
      key id comes from the certificate, and the term must end by the
      certificate's `not_after`;
    * `:root_key`: the root key signs a fresh certificate for the working
      key, as `mix aker.sign` does on a developer's machine.

  Both, or neither, answers `{:error, {:invalid, :certificate}}`, and so
  does a certificate no key in `:root_keys` signed, one for another
  working key, or one not in date now.

  Other options: `:customer`, `:seats`, and the term as either
  `:term_days` or `:term_start` plus `:term_end` (`DateTime`, UTC, start
  before end); optionally `:licence_id` (1 to 64 bytes, default a new
  UUID), `:features` (`[]`), `:serial` (1), `:moves_per_term` (20),
  `:key_id` (`"dev"`, or the certificate's) and `:now`.

  It signs only a licence `Aker.LicenceFile.verify/2` reads back, and
  answers `{:error, {:invalid, option}}` for the first option outside the
  reader's bounds, `{:error, {:invalid, :term}}` when both term forms are
  given or the range is not a term, `{:error, {:invalid, :term_end}}` when
  the term ends after the certificate, or `{:error, {:invalid, :size}}`
  when the licence would be over the reader's 4 KB.
  """
  @spec issue(binary(), keyword()) ::
          {:ok, binary()} | {:error, :bad_request | {:invalid, atom()}}
  def issue(request_bytes, opts) do
    product = Keyword.fetch!(opts, :product)
    now = opts |> Keyword.get_lazy(:now, &DateTime.utc_now/0) |> DateTime.truncate(:second)

    with {:ok, request} <- Request.verify(request_bytes, product: product),
         {:ok, signer} <- signer(opts, now),
         :ok <- check_options(opts, signer.key_id),
         {:ok, term_start, term_end} <- term(opts, now),
         :ok <- within_certificate(term_end, signer.not_after) do
      fields = %{
        "licence_id" => Keyword.get_lazy(opts, :licence_id, &uuid/0),
        "serial" => Keyword.get(opts, :serial, 1),
        "product" => product,
        "customer_name" => Keyword.fetch!(opts, :customer),
        "install_public_key" => Base.encode64(request.install_public_key),
        "machine_id_hash" => request.machine_id_hash,
        "term_start" => iso(term_start),
        "term_end" => iso(term_end),
        "seats" => Keyword.fetch!(opts, :seats),
        "moves_per_term" => Keyword.get(opts, :moves_per_term, 20),
        "features" => Keyword.get(opts, :features, []),
        "issued_at" => iso(now),
        "working_key_id" => signer.key_id
      }

      if LicenceFile.licence_fits?(Jason.encode!(fields)),
        do: {:ok, sign(fields, Keyword.fetch!(opts, :working_key), signer.certificate)},
        else: {:error, {:invalid, :size}}
    end
  end

  # The certificate the licence carries, its key id, and the end a term
  # must keep inside (nil for a certificate made here, as `mix aker.sign`
  # has always signed).
  defp signer(opts, now) do
    case {Keyword.has_key?(opts, :root_key), Keyword.has_key?(opts, :certificate)} do
      {true, false} -> {:ok, fresh_signer(opts, now)}
      {false, true} -> certified_signer(opts, now)
      _both_or_neither -> {:error, {:invalid, :certificate}}
    end
  end

  defp fresh_signer(opts, now) do
    key_id = Keyword.get(opts, :key_id, "dev")

    certificate =
      certificate(Keyword.fetch!(opts, :root_key), Keyword.fetch!(opts, :working_key),
        key_id: key_id,
        not_before: DateTime.add(now, -1, :day),
        not_after: DateTime.add(now, @certificate_days, :day)
      )

    %{key_id: key_id, certificate: certificate, not_after: nil}
  end

  defp certified_signer(opts, now) do
    working_public_key = opts |> Keyword.fetch!(:working_key) |> SigningKey.public_key()

    with %{certificate: bytes, certificate_signature: signature} = certificate <-
           Keyword.fetch!(opts, :certificate),
         {:ok, cert} <-
           LicenceFile.read_certificate(bytes, signature, Keyword.get(opts, :root_keys, [])),
         # A certificate the file cannot carry signs a licence every install refuses.
         true <- byte_size(Base.encode64(bytes)) <= LicenceFile.max_certificate_chars(),
         true <- Base.encode64(cert.public_key) == working_public_key,
         true <- DateTime.compare(now, cert.not_before) != :lt,
         true <- DateTime.compare(now, cert.not_after) != :gt do
      if Keyword.get(opts, :key_id, cert.key_id) == cert.key_id,
        do:
          {:ok,
           %{
             key_id: cert.key_id,
             certificate: Map.take(certificate, [:certificate, :certificate_signature]),
             not_after: cert.not_after
           }},
        else: {:error, {:invalid, :key_id}}
    else
      _refused -> {:error, {:invalid, :certificate}}
    end
  end

  defp term(opts, now) do
    days? = Keyword.has_key?(opts, :term_days)
    range? = Keyword.has_key?(opts, :term_start) or Keyword.has_key?(opts, :term_end)

    cond do
      days? and range? -> {:error, {:invalid, :term}}
      range? -> term_range(opts[:term_start], opts[:term_end])
      term_days?(opts[:term_days]) -> {:ok, now, DateTime.add(now, opts[:term_days], :day)}
      true -> {:error, {:invalid, :term_days}}
    end
  end

  defp term_range(%DateTime{time_zone: "Etc/UTC"} = from, %DateTime{time_zone: "Etc/UTC"} = to) do
    from = DateTime.truncate(from, :second)
    to = DateTime.truncate(to, :second)

    if DateTime.compare(from, to) == :lt and DateTime.diff(to, from, :day) <= @max_term_days and
         from.year >= 1000 and to.year <= 9999,
       do: {:ok, from, to},
       else: {:error, {:invalid, :term}}
  end

  defp term_range(_from, _to), do: {:error, {:invalid, :term}}

  defp term_days?(days), do: is_integer(days) and days in 1..@max_term_days

  defp within_certificate(_term_end, nil), do: :ok

  defp within_certificate(term_end, not_after) do
    if DateTime.compare(term_end, not_after) == :gt,
      do: {:error, {:invalid, :term_end}},
      else: :ok
  end

  # The bounds `LicenceFile` reads a licence with, so nothing signed here
  # is refused there.
  defp check_options(opts, key_id) do
    [
      customer: text?(Keyword.fetch!(opts, :customer), 400),
      seats: count?(Keyword.fetch!(opts, :seats), 0),
      licence_id: not Keyword.has_key?(opts, :licence_id) or text?(opts[:licence_id], 64),
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

  defp text?(value, max),
    do: is_binary(value) and byte_size(value) in 1..max and String.valid?(value)

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

  @doc """
  A certificate pair as one line of JSON: its two parts, base64. A
  licensing server keeps this line in one secret, and
  `decode_certificate/1` reads it back.
  """
  @spec encode_certificate(%{certificate: binary(), certificate_signature: binary()}) ::
          String.t()
  def encode_certificate(%{certificate: certificate, certificate_signature: signature}) do
    Jason.encode!(%{
      "certificate" => Base.encode64(certificate),
      "certificate_signature" => Base.encode64(signature)
    })
  end

  @doc """
  The certificate pair in `text`, as `encode_certificate/1` writes it, or
  `:error` for anything else: over 2 KB, another shape, or a part a
  licence file could not carry. It reads no signature, so `issue/2`
  checks the pair against the root keys. A refusal prints nothing of
  the input.
  """
  @spec decode_certificate(term()) ::
          {:ok, %{certificate: binary(), certificate_signature: binary()}} | :error
  def decode_certificate(text) when is_binary(text) and byte_size(text) <= @max_encoded_bytes do
    with {:ok, %{"certificate" => certificate, "certificate_signature" => signature} = map}
         when map_size(map) == 2 and is_binary(certificate) and is_binary(signature) <-
           Jason.decode(text),
         true <- byte_size(certificate) in 1..LicenceFile.max_certificate_chars(),
         {:ok, certificate} <- Base.decode64(certificate),
         {:ok, <<_::512>> = signature} <- Base.decode64(signature) do
      {:ok, %{certificate: certificate, certificate_signature: signature}}
    else
      _other -> :error
    end
  end

  def decode_certificate(_text), do: :error

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
