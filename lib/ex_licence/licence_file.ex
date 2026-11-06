defmodule ExLicence.LicenceFile do
  @moduledoc """
  Reads a signed licence file and checks every signature and field in it.

  The file is one JSON object with four base64 fields:

    * `licence`: the licence JSON bytes, signed by the issuer's working key;
    * `signature`: that signature, 64 bytes of Ed25519;
    * `certificate`: the working key's certificate JSON bytes;
    * `certificate_signature`: the root key's signature of the certificate.

  `verify/2` checks the signature over the exact bytes it received before
  it parses them, and never re-encodes the JSON. Each refusal is its own
  atom and its own log line.

  The checks run in this order, and the first failure answers:

    1. `:bad_envelope`: the file is over 64 KB, is not the four-field
       object, or a field has the wrong length or is not base64. Sizes are
       checked before anything is decoded.
    2. `:unknown_root`: no root key in `:root_keys` signed the
       certificate. An empty list refuses every file here.
    3. `:bad_certificate`: the certificate's fields are malformed, or it
       is not for a licence working key.
    4. `:bad_signature`: the certificate's key did not sign the licence.
    5. `:bad_licence`: the licence's fields are malformed.
    6. `:wrong_working_key`: the licence names another working key id.
    7. `:certificate_out_of_date`: the certificate was not in date when
       the licence was issued, or is not now.
    8. `:wrong_product`: the licence is for another product. One root key
       can sign for several products, so this check keeps one product's
       licence off another.
    9. `:wrong_machine`: the licence names another machine id.
   10. `:wrong_install_key`: the licence names another install key, or
       the install key's own error (`:install_key_missing`,
       `:install_key_unreadable`, `:install_key_timeout`) when this install
       has none to compare.
   11. `:install_key_proof_failed`: this install's key did not sign a
       fresh random value that verifies against the licence's key.
   12. `:clock_behind`: the clock reads more than a day before the latest
       time the app has seen, so setting it back cannot extend a term.
   13. `:term_not_started` or `:term_ended`.
   14. `:older_serial`: the licence is older than the one already stored.
  """

  require Logger

  alias ExLicence.InstallKey
  alias ExLicence.Terms

  @max_file_bytes 64 * 1024
  # 64 bytes of Ed25519 signature, base64 with padding.
  @signature_chars 88
  # The licence and certificate JSON caps, as base64 lengths.
  @max_licence_chars 5464
  @max_certificate_chars 1368
  @fields ~w(licence signature certificate certificate_signature)
  @clock_slack_s 24 * 60 * 60
  @purpose "licence-working-key"
  @max_features 32
  @feature ~r/\A[a-z0-9_.-]{1,32}\z/

  @type refusal ::
          :bad_envelope
          | :unknown_root
          | :bad_certificate
          | :bad_signature
          | :bad_licence
          | :wrong_working_key
          | :certificate_out_of_date
          | :wrong_product
          | :wrong_machine
          | :wrong_install_key
          | :install_key_missing
          | :install_key_unreadable
          | :install_key_timeout
          | :install_key_proof_failed
          | :clock_behind
          | :term_not_started
          | :term_ended
          | :older_serial

  @doc """
  What a working key's certificate says it is for. A root key's signature
  on any other JSON never passes as a certificate.
  """
  @spec certificate_purpose() :: String.t()
  def certificate_purpose, do: @purpose

  @doc "The largest licence file `verify/2` reads, in bytes."
  @spec max_bytes() :: pos_integer()
  def max_bytes, do: @max_file_bytes

  @doc """
  The four parts as the file's bytes. `ExLicence.Issuer` writes a
  licence through this, so the issuer and the reader share one shape.
  """
  @spec encode(%{
          licence: binary(),
          signature: binary(),
          certificate: binary(),
          certificate_signature: binary()
        }) :: binary()
  def encode(%{
        licence: licence,
        signature: signature,
        certificate: certificate,
        certificate_signature: certificate_signature
      }) do
    Jason.encode!(%{
      "licence" => Base.encode64(licence),
      "signature" => Base.encode64(signature),
      "certificate" => Base.encode64(certificate),
      "certificate_signature" => Base.encode64(certificate_signature)
    })
  end

  @doc """
  The licence in `bytes` as `ExLicence.Terms`, when every check
  passes for this install.

  Options:

    * `:product`: the product this app is (required);
    * `:root_keys`: the trusted Ed25519 root public keys, raw 32-byte
      binaries (required; see `ExLicence.PublicKeys.decode/1`);
    * `:machine_id_hash`: this host's machine id hash (required);
    * `:install_key`: `{module, opts}` of this install's key (required);
    * `:now`: the time to check against (default now);
    * `:last_seen`: the latest time the app has seen, or nil;
    * `:stored_serial`: the serial of the licence already stored, or nil.
  """
  @spec verify(binary(), keyword()) :: {:ok, Terms.t()} | {:error, refusal()}
  def verify(bytes, opts) do
    case check(bytes, opts) do
      {:ok, terms} ->
        {:ok, terms}

      {:error, reason} ->
        Logger.warning("licence refused: #{reason}")
        {:error, reason}
    end
  end

  defp check(bytes, opts) do
    # Every required option is read first, so a host that leaves one out
    # finds out on its first file, good or bad.
    product = Keyword.fetch!(opts, :product)
    root_keys = Keyword.fetch!(opts, :root_keys)
    machine_id_hash = Keyword.fetch!(opts, :machine_id_hash)
    install_key = Keyword.fetch!(opts, :install_key)
    now = Keyword.get_lazy(opts, :now, &DateTime.utc_now/0)

    with {:ok, parts} <- envelope(bytes),
         :ok <- signed_by_any(parts.certificate, parts.certificate_signature, root_keys),
         {:ok, cert} <- certificate(parts.certificate),
         :ok <- signed(parts.licence, parts.signature, cert.public_key),
         {:ok, terms} <- licence(parts.licence),
         :ok <- same(cert.key_id, terms.working_key_id, :wrong_working_key),
         :ok <- certificate_in_date(cert, terms.issued_at, now),
         :ok <- same(terms.product, product, :wrong_product),
         :ok <- same(terms.machine_id_hash, machine_id_hash, :wrong_machine),
         {:ok, public_key} <- install_public_key(install_key),
         :ok <- same(terms.install_public_key, public_key, :wrong_install_key),
         :ok <- proof(install_key, terms.install_public_key),
         :ok <- clock(now, Keyword.get(opts, :last_seen)),
         :ok <- in_term(terms, now),
         :ok <- serial(terms.serial, Keyword.get(opts, :stored_serial)) do
      {:ok, struct!(Terms, Map.delete(terms, :product))}
    end
  end

  # Step 1: sizes first, then the shape, then base64.
  defp envelope(bytes) when is_binary(bytes) and byte_size(bytes) <= @max_file_bytes do
    with {:ok, %{} = map} <- Jason.decode(bytes),
         true <- map_size(map) == 4 and Enum.all?(@fields, &Map.has_key?(map, &1)),
         true <- sized?(map),
         {:ok, licence} <- Base.decode64(map["licence"]),
         {:ok, signature} <- Base.decode64(map["signature"]),
         {:ok, certificate} <- Base.decode64(map["certificate"]),
         {:ok, certificate_signature} <- Base.decode64(map["certificate_signature"]) do
      {:ok,
       %{
         licence: licence,
         signature: signature,
         certificate: certificate,
         certificate_signature: certificate_signature
       }}
    else
      _malformed -> {:error, :bad_envelope}
    end
  end

  defp envelope(_bytes), do: {:error, :bad_envelope}

  defp sized?(%{
         "licence" => licence,
         "signature" => signature,
         "certificate" => certificate,
         "certificate_signature" => certificate_signature
       })
       when is_binary(licence) and is_binary(signature) and is_binary(certificate) and
              is_binary(certificate_signature) do
    byte_size(signature) == @signature_chars and
      byte_size(certificate_signature) == @signature_chars and
      byte_size(licence) in 1..@max_licence_chars and
      byte_size(certificate) in 1..@max_certificate_chars
  end

  defp sized?(_map), do: false

  defp signed_by_any(message, signature, keys) when is_list(keys) do
    if Enum.any?(keys, &ed25519?(message, signature, &1)),
      do: :ok,
      else: {:error, :unknown_root}
  end

  defp signed_by_any(_message, _signature, _keys), do: {:error, :unknown_root}

  defp signed(message, signature, key) do
    if ed25519?(message, signature, key), do: :ok, else: {:error, :bad_signature}
  end

  defp ed25519?(message, <<_::512>> = signature, <<_::256>> = key),
    do: :crypto.verify(:eddsa, :none, message, signature, [key, :ed25519])

  defp ed25519?(_message, _signature, _key), do: false

  # Step 3: the certificate, read only after the root key's signature held.
  defp certificate(json) do
    with {:ok,
          %{
            "purpose" => @purpose,
            "public_key" => public_key,
            "key_id" => key_id,
            "not_before" => not_before,
            "not_after" => not_after
          }} <- Jason.decode(json),
         {:ok, <<_::256>> = public_key} <- base64(public_key),
         true <- key_id?(key_id),
         {:ok, not_before} <- time(not_before),
         {:ok, not_after} <- time(not_after) do
      {:ok,
       %{public_key: public_key, key_id: key_id, not_before: not_before, not_after: not_after}}
    else
      _malformed -> {:error, :bad_certificate}
    end
  end

  # Step 5: the licence, read only after the working key's signature held.
  defp licence(json) do
    with {:ok,
          %{
            "licence_id" => licence_id,
            "serial" => serial,
            "product" => product,
            "customer_name" => customer_name,
            "install_public_key" => install_public_key,
            "machine_id_hash" => machine_id_hash,
            "term_start" => term_start,
            "term_end" => term_end,
            "seats" => seats,
            "moves_per_term" => moves_per_term,
            "issued_at" => issued_at,
            "working_key_id" => working_key_id
          } = fields} <- Jason.decode(json),
         true <- is_binary(licence_id) and byte_size(licence_id) in 1..64,
         true <- is_integer(serial) and serial > 0,
         true <- is_binary(product),
         true <- is_binary(customer_name) and byte_size(customer_name) in 1..400,
         {:ok, <<4, _::512>> = install_public_key} <- base64(install_public_key),
         true <- is_binary(machine_id_hash),
         {:ok, term_start} <- time(term_start),
         {:ok, term_end} <- time(term_end),
         true <- DateTime.compare(term_start, term_end) == :lt,
         true <- is_integer(seats) and seats >= 0,
         true <- is_integer(moves_per_term) and moves_per_term >= 0,
         {:ok, issued_at} <- time(issued_at),
         true <- key_id?(working_key_id),
         true <- features?(Map.get(fields, "features", [])) do
      {:ok,
       %{
         licence_id: licence_id,
         serial: serial,
         product: product,
         customer_name: customer_name,
         install_public_key: install_public_key,
         machine_id_hash: machine_id_hash,
         term_start: term_start,
         term_end: term_end,
         seats: seats,
         moves_per_term: moves_per_term,
         issued_at: issued_at,
         working_key_id: working_key_id,
         features: Map.get(fields, "features", [])
       }}
    else
      _malformed -> {:error, :bad_licence}
    end
  end

  @doc "Whether licence JSON `bytes` fit the size this module reads."
  @spec licence_fits?(binary()) :: boolean()
  def licence_fits?(bytes), do: byte_size(Base.encode64(bytes)) <= @max_licence_chars

  @doc """
  Whether `features` is a list a licence may carry: at most 32 names, each
  1 to 32 bytes of `a-z`, `0-9`, `_`, `.` and `-`.
  """
  @spec features?(term()) :: boolean()
  def features?(features) when is_list(features) and length(features) <= @max_features,
    do: Enum.all?(features, &(is_binary(&1) and Regex.match?(@feature, &1)))

  def features?(_features), do: false

  defp base64(value) when is_binary(value), do: Base.decode64(value)
  defp base64(_value), do: :error

  defp key_id?(key_id), do: is_binary(key_id) and byte_size(key_id) in 1..64

  # UTC only: an offset would let two files spell one time two ways.
  defp time(value) when is_binary(value) do
    case DateTime.from_iso8601(value) do
      {:ok, time, 0} -> {:ok, time}
      _other -> :error
    end
  end

  defp time(_value), do: :error

  defp same(value, value, _refusal), do: :ok
  defp same(_value, _other, refusal), do: {:error, refusal}

  defp certificate_in_date(cert, issued_at, now) do
    if in_window?(issued_at, cert.not_before, cert.not_after) and
         in_window?(now, cert.not_before, cert.not_after),
       do: :ok,
       else: {:error, :certificate_out_of_date}
  end

  defp in_window?(time, from, to),
    do: DateTime.compare(time, from) != :lt and DateTime.compare(time, to) != :gt

  defp install_public_key({module, key_opts}) do
    case module.public_key(key_opts) do
      {:ok, public_key} -> {:ok, public_key}
      {:error, reason} when is_atom(reason) -> {:error, reason}
      _other -> {:error, :install_key_unreadable}
    end
  end

  defp proof(install_key, public_key) do
    if InstallKey.proves?(install_key, public_key),
      do: :ok,
      else: {:error, :install_key_proof_failed}
  end

  defp clock(_now, nil), do: :ok

  defp clock(now, %DateTime{} = last_seen) do
    if DateTime.diff(last_seen, now) > @clock_slack_s,
      do: {:error, :clock_behind},
      else: :ok
  end

  # A latest time the host cannot give as a DateTime proves nothing about
  # the clock, so it refuses.
  defp clock(_now, _last_seen), do: {:error, :clock_behind}

  defp in_term(terms, now) do
    cond do
      DateTime.compare(now, terms.term_start) == :lt -> {:error, :term_not_started}
      DateTime.compare(now, terms.term_end) != :lt -> {:error, :term_ended}
      true -> :ok
    end
  end

  defp serial(_serial, nil), do: :ok
  defp serial(serial, stored) when serial >= stored, do: :ok
  defp serial(_serial, _stored), do: {:error, :older_serial}
end
