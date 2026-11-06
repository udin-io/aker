defmodule ExLicence.PublicKeysTest do
  @moduledoc """
  Decoding a host's list of Ed25519 public keys: raw 32-byte keys, base64,
  with a malformed entry named by its place, never its value.
  """
  use ExUnit.Case, async: true

  alias ExLicence.PublicKeys

  @good "c5l19pS6v3pARUswDBjEEVJ/lTJLE8B0KyE9NOhV2OA="

  test "decode takes raw 32-byte keys, base64" do
    assert {:ok, [<<_::256>> = key, key]} = PublicKeys.decode([@good, @good])
    assert key == Base.decode64!(@good)
    assert PublicKeys.decode([]) == {:ok, []}
  end

  test "a malformed entry is refused by its place in the list" do
    for bad <- [
          "c5l19pS6v3pARUswDBjEEVJ/lTJLE8B0KyE9NOhV2OA",
          "c5l19pS6v3pARUswDBjEEVJ/lTJLE8B0KyE9NOhV2O==",
          Base.encode64(:crypto.strong_rand_bytes(31)),
          Base.encode64(:crypto.strong_rand_bytes(33)),
          " " <> @good,
          @good <> "\n",
          "-----BEGIN PUBLIC KEY-----",
          :crypto.strong_rand_bytes(32),
          nil,
          ~c"charlist"
        ] do
      assert PublicKeys.decode([@good, bad]) == {:error, 2}, inspect(bad)
    end

    assert PublicKeys.decode("not a list") == {:error, 1}
  end
end
