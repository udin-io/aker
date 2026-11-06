defmodule ExLicence.PublicKeys do
  @moduledoc """
  Ed25519 public keys as a host's config lists them: raw 32-byte keys,
  base64. A host decodes its root key list through `decode/1` at boot and
  stops on an error, which names the entry's place in the list and never
  its value.
  """

  @doc """
  `entries` as raw keys, or `{:error, place}` with the 1-based place of
  the first entry that is not a base64 32-byte key.
  """
  @spec decode(term()) :: {:ok, [<<_::256>>]} | {:error, pos_integer()}
  def decode(entries) when is_list(entries) do
    entries
    |> Enum.with_index(1)
    |> Enum.reduce_while({:ok, []}, fn {entry, place}, {:ok, keys} ->
      case key(entry) do
        {:ok, key} -> {:cont, {:ok, [key | keys]}}
        :error -> {:halt, {:error, place}}
      end
    end)
    |> case do
      {:ok, keys} -> {:ok, Enum.reverse(keys)}
      error -> error
    end
  end

  def decode(_entries), do: {:error, 1}

  defp key(entry) when is_binary(entry) do
    # `Base.decode64/1` takes only the base64 alphabet with exact padding,
    # and the match takes only 32 bytes.
    case Base.decode64(entry) do
      {:ok, <<_::256>> = key} -> {:ok, key}
      _malformed -> :error
    end
  end

  defp key(_entry), do: :error
end
