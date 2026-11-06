defmodule Aker.TestSupport.LicensingServer do
  @moduledoc """
  A stand-in for the licensing server behind `Req.Test`. It checks each
  signed call with `Aker.SignedCall.verify/2`, as a real server would,
  then refuses a key it does not know. It records every call, so a test can
  count them, and answers with what the test hands it.
  """

  import Plug.Conn

  alias Aker.SignedCall

  @base_url "https://licensing.test"

  @doc "The gate's `server:` option for this stand-in."
  def server(extra \\ []),
    do: Keyword.merge([base_url: @base_url, req_options: [plug: {Req.Test, __MODULE__}]], extra)

  @doc """
  Serves `answer` for every call: `{:licence, bytes}`, `{:refuse, status,
  code}`, `{:raw, status, headers, body}` or `:down`. `known_key` is the
  install public key the server stores. Answers the agent that records the
  calls.
  """
  def start(answer, known_key) do
    {:ok, agent} = Agent.start_link(fn -> %{calls: [], nonces: MapSet.new()} end)
    Req.Test.stub(__MODULE__, fn conn -> handle(conn, answer, known_key, agent) end)
    agent
  end

  @doc "The calls made so far, oldest first: `%{path, verdict, body}`."
  def calls(agent), do: agent |> Agent.get(& &1.calls) |> Enum.reverse()

  defp handle(conn, answer, known_key, agent) do
    {:ok, body, conn} = read_body(conn)
    verdict = verdict(conn, body, known_key, agent)

    Agent.update(
      agent,
      &%{&1 | calls: [%{path: conn.request_path, verdict: verdict, body: body} | &1.calls]}
    )

    case {verdict, answer} do
      {:ok, {:licence, bytes}} -> json(conn, 200, %{"licence_file" => bytes})
      {:ok, {:refuse, status, code}} -> json(conn, status, %{"error" => code})
      {:ok, {:raw, status, headers, raw}} -> raw(conn, status, headers, raw)
      {:ok, :down} -> json(conn, 503, %{"error" => "unavailable"})
      {refusal, _answer} -> json(conn, 401, %{"error" => Atom.to_string(refusal)})
    end
  end

  # Activation carries the code, not an install signature.
  defp verdict(%{request_path: "/api/v1/activate"}, _body, _known_key, _agent), do: :ok

  defp verdict(conn, body, known_key, agent) do
    call = %{method: conn.method, path: conn.request_path, headers: conn.req_headers, body: body}

    case SignedCall.verify(call, nonce_fresh?: &fresh?(agent, &1)) do
      {:ok, ^known_key} -> :ok
      {:ok, _other_key} -> :unknown_install
      {:error, reason} -> reason
    end
  end

  defp fresh?(agent, nonce) do
    Agent.get_and_update(agent, fn state ->
      {not MapSet.member?(state.nonces, nonce),
       %{state | nonces: MapSet.put(state.nonces, nonce)}}
    end)
  end

  defp json(conn, status, map) do
    conn
    |> put_resp_content_type("application/json")
    |> send_resp(status, Jason.encode!(map))
  end

  defp raw(conn, status, headers, body) do
    headers
    |> Enum.reduce(conn, fn {name, value}, conn -> put_resp_header(conn, name, value) end)
    |> send_resp(status, body)
  end
end
