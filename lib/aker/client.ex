defmodule Aker.Client do
  @moduledoc """
  The app's calls to the licensing server, under `/api/v1`, JSON both ways.

    * `activate/3` sends an activation code and this install's activation
      request, and gets the first licence back. It is the one call the
      install key does not sign: the code is the credential, and the
      request inside is signed by the install key.
    * `renew/3` and `refresh/3` carry the licence id and serial, and are
      signed by the install key (`Aker.SignedCall`).

  Every call is made once: retries and redirects are off, so a failing
  server costs one call per attempt. The answer is read raw and capped at
  64 KB as it arrives. A server's answer is `{:ok, licence_file_bytes}` or
  `{:error, reason}`, where a refusal code the server names is
  `{:refused, code}` with the code kept as text of at most 64 characters,
  never turned into an atom.

  `server` options:

    * `:base_url`: the server, `https://` only;
    * `:allow_http`: true lets an `http://` base URL through, for tests;
    * `:req_options`: merged into each `Req` call, such as a test plug;
    * `:setting`: the setting name a log line tells the operator to set
      when there is no base URL (default `"server_url"`).
  """

  require Logger

  alias Aker.SignedCall

  @timeout_ms 15_000
  @max_body_bytes 64 * 1024

  @doc "Activates with `code`, sending the activation request's bytes."
  @spec activate(keyword(), String.t(), binary()) :: {:ok, binary()} | {:error, term()}
  def activate(server, code, request_bytes) do
    body = Jason.encode!(%{"code" => code, "request" => Jason.decode!(request_bytes)})

    with {:ok, base} <- base_url(server), do: post(server, base, "/api/v1/activate", body, [])
  end

  @doc "Asks for the next term's licence, signed by `install_key`."
  @spec renew(keyword(), {module(), keyword()}, map()) :: {:ok, binary()} | {:error, term()}
  def renew(server, install_key, licence),
    do: signed_post(server, "/api/v1/renew", install_key, licence)

  @doc "Asks for this term's licence with the current seats, signed by `install_key`."
  @spec refresh(keyword(), {module(), keyword()}, map()) :: {:ok, binary()} | {:error, term()}
  def refresh(server, install_key, licence),
    do: signed_post(server, "/api/v1/refresh", install_key, licence)

  defp signed_post(server, path, install_key, licence) do
    body = Jason.encode!(%{"licence_id" => licence.licence_id, "serial" => licence.serial})

    with {:ok, base} <- base_url(server),
         # The path the server reads, the base URL's own path included.
         signed_path = URI.parse(base <> path).path || path,
         {:ok, headers} <- SignedCall.headers(install_key, "POST", signed_path, body) do
      post(server, base, path, body, headers)
    end
  end

  defp base_url(server) do
    case Keyword.get(server, :base_url) do
      url when is_binary(url) and url != "" -> scheme(String.trim_trailing(url, "/"), server)
      _unset -> no_url(server)
    end
  end

  defp scheme("https://" <> _rest = url, _server), do: {:ok, url}

  defp scheme("http://" <> _rest = url, server) do
    if Keyword.get(server, :allow_http, false), do: {:ok, url}, else: insecure()
  end

  defp scheme(_url, _server), do: insecure()

  defp insecure do
    Logger.error("licensing: the licensing server's address must start with https://")
    {:error, :insecure_url}
  end

  defp no_url(server) do
    Logger.error(
      "licensing: no licensing server. Set #{Keyword.get(server, :setting, "server_url")}."
    )

    {:error, :no_licensing_url}
  end

  defp post(server, base, path, body, headers) do
    [
      url: base <> path,
      method: :post,
      body: body,
      headers: [{"content-type", "application/json"} | headers],
      retry: false,
      redirect: false,
      receive_timeout: @timeout_ms,
      decode_body: false,
      # No gzip: the body is read raw and capped as it arrives, so a bad
      # answer cannot fill memory.
      compressed: false,
      raw: true,
      into: &capped/2
    ]
    |> Keyword.merge(Keyword.get(server, :req_options, []))
    |> Req.request()
    |> answer(path)
  end

  defp capped({:data, data}, {request, response}) do
    body = response.body <> data

    if byte_size(body) > @max_body_bytes,
      do: {:halt, {request, %{response | body: :too_large}}},
      else: {:cont, {request, %{response | body: body}}}
  end

  defp answer({:ok, %Req.Response{body: :too_large}}, path) do
    Logger.warning("licensing: #{path} answered more than 64 KB")
    {:error, :bad_answer}
  end

  defp answer({:ok, %Req.Response{status: 200, body: body}}, _path) when is_binary(body) do
    case Jason.decode(body) do
      {:ok, %{"licence_file" => file}} when is_binary(file) -> {:ok, file}
      _other -> {:error, :bad_answer}
    end
  end

  defp answer({:ok, %Req.Response{status: status, body: body}}, path) when is_binary(body) do
    code =
      case Jason.decode(String.slice(body, 0, 4096)) do
        {:ok, %{"error" => code}} when is_binary(code) -> String.slice(code, 0, 64)
        _other -> "http_#{status}"
      end

    Logger.warning("licensing: #{path} refused: #{inspect(code)}")
    {:error, {:refused, code}}
  end

  defp answer({:error, exception}, path) do
    Logger.warning("licensing: #{path} unreachable: #{Exception.message(exception)}")
    {:error, :unreachable}
  end
end
