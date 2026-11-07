defmodule Mix.Tasks.Aker.Certify do
  @moduledoc """
  Certify a working key with the root key, offline, so a licensing server
  can sign licences without ever holding the root key.

      mix aker.certify --root-key ../keys/root.pem \\
        --working-key ../keys/working-2026-11.pem --key-id w-2026-11

  Options:

    * `--root-key` (required): the root key's PEM.
    * `--working-key` (required): the working key's PEM, the key the server
      will sign with.
    * `--key-id` (required): 1 to 64 bytes; every licence the working key
      signs names it.
    * `--days` (default 470): how long the certificate lasts, 1 to 600.
      An install refuses a licence once its certificate ends, so the
      certificate must outlast every term the server signs with it.
    * `--not-before` (default now): when the certificate starts, as ISO
      8601, such as `2026-11-07T00:00:00Z`.

  Keep both keys outside the checkout: the task refuses a key inside the
  folder it runs in. It prints the key id, the certificate on one line
  (the value the server keeps, which `Aker.Issuer.decode_certificate/1`
  reads), and the root key's public half. It never prints the working
  key.
  """
  use Mix.Task

  alias Aker.Issuer
  alias Aker.SigningKey

  @shortdoc "Certify a working key with the root key"

  @switches [
    root_key: :string,
    working_key: :string,
    key_id: :string,
    days: :string,
    not_before: :string
  ]

  @usage "usage: mix aker.certify --root-key <pem> --working-key <pem> --key-id <id> " <>
           "[--days 470] [--not-before <iso8601>]"

  @impl Mix.Task
  def run(argv) do
    {opts, args} = OptionParser.parse!(argv, strict: @switches)

    if args != [] or not is_binary(opts[:root_key]) or not is_binary(opts[:working_key]) or
         not is_binary(opts[:key_id]),
       do: Mix.raise(@usage)

    key_id = opts[:key_id]

    if byte_size(key_id) not in 1..64, do: Mix.raise("--key-id is 1 to 64 bytes")

    days = days(Keyword.get(opts, :days, "470"))
    not_before = not_before(opts[:not_before])
    root_key = load(opts[:root_key])
    working_key = load(opts[:working_key])
    not_after = DateTime.add(not_before, days, :day)

    if SigningKey.public_key(working_key) == SigningKey.public_key(root_key),
      do: Mix.raise("--working-key is the root key; certify a separate working key")

    if not_after.year > 9999,
      do: Mix.raise("the certificate ends after the year 9999; use an earlier --not-before")

    certificate =
      Issuer.certificate(root_key, working_key,
        key_id: key_id,
        not_before: not_before,
        not_after: not_after
      )

    Mix.shell().info("Key id: #{key_id}")
    Mix.shell().info("Certificate:\n" <> Issuer.encode_certificate(certificate))

    Mix.shell().info(
      "Installs accept licences under it when their root keys list " <>
        SigningKey.public_key(root_key) <> "."
    )
  end

  defp days(text) do
    case Integer.parse(text) do
      {days, ""} when days in 1..600 -> days
      _other -> Mix.raise("--days is 1 to 600")
    end
  end

  defp not_before(nil), do: DateTime.truncate(DateTime.utc_now(), :second)

  defp not_before(text) do
    case DateTime.from_iso8601(text) do
      {:ok, time, _offset} -> DateTime.truncate(time, :second)
      _other -> Mix.raise("--not-before is a time in ISO 8601, such as 2026-11-07T00:00:00Z")
    end
  end

  defp load(path) do
    case SigningKey.load(Path.expand(path), File.cwd!()) do
      {:ok, key} -> key
      {:error, message} -> Mix.raise(message)
    end
  end
end
