defmodule Mix.Tasks.Aker.Sign do
  @moduledoc """
  Sign a licence from an install's activation request, standing in for the
  licensing server on your own machine.

      mix aker.sign request.json --product my_app \\
        --root-key ../keys/root.pem --customer "Acme Logistics" \\
        --seats 10 --term monthly

  Options:

    * `--product` (required): the product the request and licence name.
    * `--root-key` (required): the root key's PEM, which signs the working
      key's certificate. Keep it outside the checkout: the task refuses a
      key inside the folder it runs in.
    * `--working-key`: the working key's PEM, which signs the licence
      (default: the root key).
    * `--customer`, `--seats` (required).
    * `--term` (required): `monthly` (30 days), `yearly` (365 days) or a
      number of days.
    * `--features`: the features the licence sells, comma-separated, such
      as `--features reports,export`.
    * `--limits`: the named limits the licence sells, comma-separated
      `name=value` pairs, each value a whole number or `unlimited`, such as
      `--limits clients=5,messages_per_month=unlimited`. `--limits ""`
      names none.
    * `--serial` (default 1): raise it for each licence after the first,
      since an app refuses a licence older than the one it holds.
    * `--key-id` (default `dev`), `--moves` (default 20).
    * `--out` (default `licence.json` beside the request).

  The keys are PEM files `openssl genpkey -algorithm ed25519` writes, held
  as `Aker.SigningKey`, so nothing prints key material. The last line
  prints the root key's public half: the app accepts the licence only when
  its root key list holds that value.
  """
  use Mix.Task

  alias Aker.Issuer
  alias Aker.Request
  alias Aker.SigningKey

  @shortdoc "Sign a licence from an activation request"

  @switches [
    product: :string,
    root_key: :string,
    working_key: :string,
    customer: :string,
    seats: :integer,
    term: :string,
    features: :string,
    limits: :keep,
    serial: :integer,
    key_id: :string,
    moves: :integer,
    out: :string
  ]

  @usage "usage: mix aker.sign <request> --product <name> --root-key <pem> " <>
           "--customer <name> --seats <n> --term monthly|yearly|<days> " <>
           "[--features <a,b>] [--limits <name=n,...>] [--working-key <pem>] [--serial <n>] [--key-id <id>] " <>
           "[--moves <n>] [--out <file>]"

  @limits_message "--limits is at most 32 name=value pairs, each name 1 to 32 bytes of " <>
                    "a-z, 0-9, _, . and -, used once, each value a whole number up to " <>
                    "9007199254740991 or unlimited"

  # What each bound `Aker.Issuer` checks says, in the task's own words.
  @invalid %{
    customer: "--customer is 1 to 400 bytes",
    seats: "--seats is 0 or more",
    term_days: "--term is at most 36500 days",
    serial: "--serial is 1 or more",
    moves_per_term: "--moves is 0 or more",
    key_id: "--key-id is 1 to 64 bytes",
    features: "--features is at most 32 names, each 1 to 32 bytes of a-z, 0-9, _, . and -",
    limits: @limits_message,
    size: "the licence is over 4 KB; use a shorter customer name, fewer features or fewer limits"
  }

  @impl Mix.Task
  def run(argv) do
    {opts, args} = OptionParser.parse!(argv, strict: @switches)
    request_path = request_path!(args, opts)
    # `--features ""` names no feature; an empty name between commas is refused.
    features =
      if opts[:features] in [nil, ""], do: [], else: String.split(opts[:features], ",")

    limits = opts |> Keyword.get_values(:limits) |> limits()

    if not Request.product?(opts[:product]),
      do: Mix.raise("--product is 1 to 64 characters of a-z, 0-9, _ and -")

    root_key = load(opts[:root_key])
    working_key = if opts[:working_key], do: load(opts[:working_key]), else: root_key

    issued =
      request_path
      |> File.read!()
      |> Issuer.issue(
        product: opts[:product],
        root_key: root_key,
        working_key: working_key,
        customer: opts[:customer],
        seats: opts[:seats],
        term_days: term_days(opts[:term]),
        features: features,
        limits: limits,
        serial: Keyword.get(opts, :serial, 1),
        key_id: Keyword.get(opts, :key_id, "dev"),
        moves_per_term: Keyword.get(opts, :moves, 20)
      )

    licence =
      case issued do
        {:ok, licence} ->
          licence

        {:error, :bad_request} ->
          Mix.raise("#{request_path} is not a signed #{opts[:product]} activation request")

        {:error, {:invalid, option}} ->
          Mix.raise(@invalid[option])
      end

    out = Path.expand(opts[:out] || Path.join(Path.dirname(request_path), "licence.json"))
    File.write!(out, licence)

    Mix.shell().info(
      "Signed #{out}. The app accepts it when its root keys list " <>
        SigningKey.public_key(root_key) <> "."
    )
  end

  defp request_path!(args, opts) do
    case {args, opts[:product], opts[:root_key], opts[:customer], opts[:seats], opts[:term]} do
      {[request], product, root, customer, seats, term}
      when is_binary(product) and is_binary(root) and is_binary(customer) and
             is_integer(seats) and seats >= 0 and is_binary(term) ->
        Path.expand(request)

      _other ->
        Mix.raise(@usage)
    end
  end

  defp load(path) do
    case SigningKey.load(Path.expand(path), File.cwd!()) do
      {:ok, key} -> key
      {:error, message} -> Mix.raise(message)
    end
  end

  # The issuer checks each name and number again; the task refuses here
  # only what a map cannot carry to it: a pair that is not name=value, a
  # value that is not a number, and a name given twice.
  defp limits([]), do: %{}
  defp limits([""]), do: %{}
  defp limits([text]), do: limit_map(text)
  defp limits(_twice), do: Mix.raise("--limits is given once, with every pair in it")

  defp limit_map(text) do
    pairs = text |> String.split(",") |> Enum.map(&limit_pair/1)
    names = Enum.map(pairs, &elem(&1, 0))

    if names == Enum.uniq(names),
      do: Map.new(pairs),
      else: Mix.raise(@limits_message)
  end

  defp limit_pair(pair) do
    with [name, value] <- String.split(pair, "="),
         {:ok, value} <- limit_value(value) do
      {name, value}
    else
      _bad -> Mix.raise(@limits_message)
    end
  end

  defp limit_value("unlimited"), do: {:ok, :unlimited}

  # Digits only, written the one way `Integer.to_string/1` writes them, so
  # "+5" and "007" are refused rather than read as 5 and 7.
  defp limit_value(text) do
    case Integer.parse(text) do
      {value, ""} when value >= 0 ->
        if Integer.to_string(value) == text, do: {:ok, value}, else: :error

      {value, ""} ->
        {:ok, value}

      _other ->
        :error
    end
  end

  defp term_days("monthly"), do: 30
  defp term_days("yearly"), do: 365

  defp term_days(days) do
    case Integer.parse(days) do
      {days, ""} when days > 0 -> days
      _other -> Mix.raise("--term is monthly, yearly or a number of days above 0")
    end
  end
end
