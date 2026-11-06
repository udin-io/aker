defmodule Aker.MachineId do
  @moduledoc """
  The host's identity a licence names: the SHA-256 of its machine id file,
  lowercase hex.

  On Linux that file is `/etc/machine-id`. Inside a container that path
  holds the image's id, which every container of the image shares, so an
  on-prem install bind-mounts the host's file into the container read-only
  and passes its path here. The hostname changes on every recreate, and
  `/sys/class/dmi/id/product_uuid` is readable by root alone, so neither
  serves.
  """

  @max_bytes 256

  # Reads at most a little past the cap, so a path to a large file or a
  # device that never ends costs no memory.
  defp read_head(path) do
    case File.open(path, [:read, :binary], &IO.binread(&1, @max_bytes + 2)) do
      # Longer than an id and its newline: the file runs past the cap.
      {:ok, text} when is_binary(text) and byte_size(text) <= @max_bytes + 1 -> {:ok, text}
      _missing_or_empty -> :error
    end
  end

  @doc "The hash of the machine id in the file at `path`."
  @spec hash(Path.t()) :: {:ok, String.t()} | {:error, :machine_id_missing}
  def hash(path) do
    # A machine id is 32 hex characters and a newline; anything much
    # longer is not one.
    with {:ok, text} <- read_head(path),
         id = String.trim(text),
         true <- id != "" and byte_size(id) <= @max_bytes do
      {:ok, :crypto.hash(:sha256, id) |> Base.encode16(case: :lower)}
    else
      _missing -> {:error, :machine_id_missing}
    end
  end
end
