defmodule Aker.Store do
  @moduledoc """
  Where a host keeps its licence. The gate reads and writes it only through
  this behaviour, so the library takes no database dependency.

  A record is any map or struct with `:envelope` (the licence file's
  bytes), `:licence_id`, `:serial`, `:term_end` and `:last_seen_at`.
  `store/3`'s attributes add `:customer_name`, `:seats`, `:features`,
  `:limits` (as `Aker.Terms` reads them) and `:term_start`. A store keeps
  only the attributes it has columns for: the stored licence file holds
  them all.

  The `actor` passes from the host's call to `store/3` untouched; the gate
  never reads it. A renewal stores as `:system`. The store decides who may
  write, and answers `{:error, :forbidden}` to anyone else.

  Each callback gets the `opts` of the gate's `store: {module, opts}`.
  """

  @type record :: map()

  @doc "The newest licence by serial, `nil` when none is stored."
  @callback current(opts :: keyword()) :: {:ok, record() | nil} | {:error, term()}

  @doc "Stores a licence that passed every check."
  @callback store(attrs :: map(), actor :: term(), opts :: keyword()) ::
              {:ok, record()} | {:error, :forbidden} | {:error, :not_stored}

  @doc "Moves the latest time seen on `record`."
  @callback touch(record(), last_seen_at :: DateTime.t(), opts :: keyword()) ::
              {:ok, record()} | {:error, term()}
end
