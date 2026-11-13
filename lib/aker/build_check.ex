defmodule Aker.BuildCheck do
  @moduledoc """
  Whether a build may compile and start, from what it was built with. A
  customer build must check the licence, trust at least one root key, and
  never trust a development key, whose private half sits in the app's own
  repository.

  An app calls `check/1` at compile time and again at boot, and maps each
  refusal to a sentence that names its own settings. A build that is not
  for a customer (dev, test, the app maker's own servers) passes.
  """

  @type refusal :: :licence_check_off | :no_root_key | :bad_root_key | :dev_root_key

  @doc """
  `:ok`, or the first refusal for `build`:

    * `:customer?`: whether the build ships to a customer. Anything but
      `false` counts as a customer build;
    * `:enforced?`: whether the licence check runs. Anything but `true`
      answers `:licence_check_off`;
    * `:root_keys`: the root public keys the build trusts, base64, as a
      list or as one text of comma-separated keys. `nil`, empty or blank
      answers `:no_root_key`; an entry that is not 32 bytes of base64
      answers `:bad_root_key`;
    * `:dev_keys`: the app's development root public keys, base64. A
      trusted key equal to one, as bytes, answers `:dev_root_key`. A
      malformed entry here is the app's own bug, and raises. An empty list
      checks for no development key at all, so pass every key whose private
      half sits in a repository or a developer's machine.
  """
  @spec check(%{
          customer?: boolean(),
          enforced?: boolean(),
          root_keys: [String.t()] | String.t() | nil,
          dev_keys: [String.t()]
        }) :: :ok | {:error, refusal()}
  def check(%{customer?: false}), do: :ok

  def check(%{enforced?: enforced?, root_keys: root_keys, dev_keys: dev_keys}) do
    dev = Enum.map(dev_keys, &dev_key!/1)

    cond do
      enforced? != true -> {:error, :licence_check_off}
      entries(root_keys) == [] -> {:error, :no_root_key}
      true -> check_keys(entries(root_keys), dev)
    end
  end

  defp entries(nil), do: []

  defp entries(text) when is_binary(text) do
    if String.trim(text) == "",
      do: [],
      else: text |> String.split(",") |> Enum.map(&String.trim/1) |> drop_blank_list()
  end

  defp entries(list) when is_list(list), do: list
  defp entries(_other), do: [:malformed]

  # A text of only commas and spaces trusts nothing; any other blank entry
  # between keys is a typo in a key list and refuses as a bad key.
  defp drop_blank_list(entries) do
    if Enum.all?(entries, &(&1 == "")), do: [], else: entries
  end

  # Compared as bytes: base64 ignores the last character's two spare bits,
  # so one key has several spellings.
  defp check_keys(entries, dev) do
    keys = Enum.map(entries, &decode/1)

    cond do
      :error in keys -> {:error, :bad_root_key}
      Enum.any?(keys, &(&1 in dev)) -> {:error, :dev_root_key}
      true -> :ok
    end
  end

  defp decode(entry) when is_binary(entry) do
    case Base.decode64(entry) do
      {:ok, <<_::256>> = key} -> key
      _malformed -> :error
    end
  end

  defp decode(_entry), do: :error

  defp dev_key!(entry) do
    case decode(entry) do
      :error -> raise ArgumentError, "a development root key is not 32 bytes of base64"
      key -> key
    end
  end
end
