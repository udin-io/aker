defmodule Aker.SignedCall do
  @moduledoc """
  A call to the licensing server signed by the install key, and the check a
  server runs on one.

  A signed call carries four headers:

    * `x-licence-install-key`: the install public key, base64;
    * `x-licence-timestamp`: Unix seconds;
    * `x-licence-nonce`: 16 random bytes, base64;
    * `x-licence-signature`: the install key's DER signature, base64, of
      `signed_string/5`.

  `verify/2` answers the install public key only when the signature holds.
  The server then looks that key up itself: a valid signature proves the
  caller holds the key, not that the server knows it.
  """

  alias Aker.InstallKey

  @window_s 600
  @headers ~w(x-licence-install-key x-licence-timestamp x-licence-nonce x-licence-signature)

  @doc """
  The text the install key signs for one call: the method, the path, the
  timestamp, the nonce and the body's SHA-256 in hex, one per line.
  """
  @spec signed_string(String.t(), String.t(), String.t(), String.t(), binary()) :: binary()
  def signed_string(method, path, timestamp, nonce, body) do
    Enum.join(
      [
        method,
        path,
        timestamp,
        nonce,
        :crypto.hash(:sha256, body) |> Base.encode16(case: :lower)
      ],
      "\n"
    )
  end

  @doc """
  The four headers for a call of `method` to `path` with `body`, signed by
  `install_key` (`{module, opts}`). `:now` (Unix seconds) sets the
  timestamp, for tests.
  """
  @spec headers({module(), keyword()}, String.t(), String.t(), binary(), keyword()) ::
          {:ok, [{String.t(), String.t()}]} | {:error, atom()}
  def headers({module, key_opts}, method, path, body, opts \\ []) do
    timestamp = Integer.to_string(Keyword.get_lazy(opts, :now, fn -> System.os_time(:second) end))
    nonce = Base.encode64(:crypto.strong_rand_bytes(16))

    with {:ok, public_key} <- module.public_key(key_opts),
         {:ok, signature} <-
           module.sign(signed_string(method, path, timestamp, nonce, body), key_opts) do
      {:ok,
       [
         {"x-licence-install-key", Base.encode64(public_key)},
         {"x-licence-timestamp", timestamp},
         {"x-licence-nonce", nonce},
         {"x-licence-signature", Base.encode64(signature)}
       ]}
    end
  end

  @doc """
  Checks a signed call as a server receives it: `%{method:, path:,
  headers:, body:}`, where `headers` is a list of `{name, value}` with
  lowercase names, as Plug gives them.

  Options:

    * `:nonce_fresh?` (required): a 1-arity function over the nonce's text
      that answers true the first time it sees a nonce and false after, kept
      over the server's own nonce table. It runs only once every other check
      has passed, so a forged call records no nonce. A timestamp may sit up to
      `:window_s` ahead of now, so keep each nonce for twice `:window_s`.
    * `:now`: Unix seconds (default now);
    * `:window_s`: how far the timestamp may sit from now (default 600).

  Answers `{:ok, install_public_key}`, or `{:error, reason}` with reason
  `:unsigned`, `:bad_key`, `:bad_nonce`, `:stale`, `:bad_signature` or
  `:replayed`.
  """
  @spec verify(map(), keyword()) :: {:ok, binary()} | {:error, atom()}
  def verify(%{method: method, path: path, headers: headers, body: body}, opts)
      when is_binary(method) and is_binary(path) and is_list(headers) and is_binary(body) do
    fresh? = Keyword.fetch!(opts, :nonce_fresh?)
    now = Keyword.get_lazy(opts, :now, fn -> System.os_time(:second) end)
    window = Keyword.get(opts, :window_s, @window_s)

    with {:ok, [key, timestamp, nonce, signature]} <- fetch(headers),
         {:ok, key} <- key(key),
         :ok <- nonce(nonce),
         :ok <- in_window(timestamp, now, window),
         {:ok, signature} <- decode(signature, :bad_signature),
         true <-
           InstallKey.verify(key, signed_string(method, path, timestamp, nonce, body), signature) ||
             {:error, :bad_signature},
         true <- fresh?.(nonce) == true || {:error, :replayed} do
      {:ok, key}
    end
  end

  def verify(_call, _opts), do: {:error, :unsigned}

  # Exactly one of each header; a second copy could make two readers
  # disagree about which one was signed.
  defp fetch(headers) do
    values =
      for name <- @headers do
        for {header, value} <- headers, header == name, do: value
      end

    if Enum.all?(values, &match?([value] when is_binary(value), &1)),
      do: {:ok, Enum.map(values, &hd/1)},
      else: {:error, :unsigned}
  end

  defp key(text) do
    case Base.decode64(text) do
      {:ok, <<4, _::512>> = key} -> if InstallKey.point?(key), do: {:ok, key}, else: bad_key()
      _other -> bad_key()
    end
  end

  defp bad_key, do: {:error, :bad_key}

  defp nonce(text) do
    case Base.decode64(text) do
      {:ok, <<_::128>>} -> :ok
      _other -> {:error, :bad_nonce}
    end
  end

  defp in_window(text, now, window) do
    with true <- Regex.match?(~r/\A[0-9]{1,12}\z/, text),
         {time, ""} when abs(now - time) <= window <- Integer.parse(text) do
      :ok
    else
      _other -> {:error, :stale}
    end
  end

  defp decode(text, refusal) do
    case Base.decode64(text) do
      {:ok, bytes} -> {:ok, bytes}
      :error -> {:error, refusal}
    end
  end
end
