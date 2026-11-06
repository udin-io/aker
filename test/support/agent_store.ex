defmodule Aker.TestSupport.AgentStore do
  @moduledoc """
  An `Aker.Store` over an Agent, for tests. It stores for the actors
  `:admin` and `:system` and answers `:forbidden` to every other, as a
  host's own store checks who may write. `fail_reads: true` answers every
  read with an error, as a store that cannot be read.
  """
  @behaviour Aker.Store

  @doc "A fresh store, as the gate's `store:` option."
  def start do
    {:ok, agent} = Agent.start_link(fn -> [] end)
    {__MODULE__, agent: agent}
  end

  @doc "Every stored record, newest serial first."
  def rows({__MODULE__, opts}), do: Agent.get(opts[:agent], & &1)

  @impl true
  def current(opts) do
    if opts[:fail_reads],
      do: {:error, :database_down},
      else: {:ok, Agent.get(opts[:agent], &List.first/1)}
  end

  @impl true
  def store(attrs, actor, opts) when actor in [:admin, :system] do
    Agent.update(opts[:agent], fn rows -> Enum.sort_by([attrs | rows], & &1.serial, :desc) end)
    {:ok, attrs}
  end

  def store(_attrs, _actor, _opts), do: {:error, :forbidden}

  @impl true
  def touch(record, last_seen_at, opts) do
    touched = %{record | last_seen_at: last_seen_at}

    Agent.update(opts[:agent], fn rows ->
      Enum.map(rows, &if(&1.licence_id == record.licence_id, do: touched, else: &1))
    end)

    {:ok, touched}
  end
end
