defmodule Aker.BuildCheckTest do
  @moduledoc """
  A customer build must check the licence, trust at least one root key,
  and never trust the development key, whose private half sits in the
  app's own repository. Each refusal changes one field of the control.
  """
  use ExUnit.Case, async: true

  alias Aker.BuildCheck

  @dev :crypto.strong_rand_bytes(32) |> Base.encode64()
  @root :crypto.strong_rand_bytes(32) |> Base.encode64()

  defp build(extra \\ %{}),
    do: Map.merge(%{customer?: true, enforced?: true, root_keys: @root, dev_keys: [@dev]}, extra)

  test "a customer build that checks the licence and trusts a real root key passes" do
    assert BuildCheck.check(build()) == :ok
    assert BuildCheck.check(build(%{root_keys: [@root]})) == :ok
    assert BuildCheck.check(build(%{root_keys: "#{@root}, #{Base.encode64(<<1::256>>)}"})) == :ok
  end

  test "a build that is not for a customer passes whatever it trusts" do
    assert BuildCheck.check(build(%{customer?: false, enforced?: false, root_keys: nil})) == :ok
    assert BuildCheck.check(build(%{customer?: false, root_keys: @dev})) == :ok
  end

  test "a customer build with the licence check off is refused" do
    for enforced <- [false, nil, :skip, "true"] do
      assert BuildCheck.check(build(%{enforced?: enforced})) == {:error, :licence_check_off},
             inspect(enforced)
    end
  end

  test "a customer build trusting no root key is refused" do
    for keys <- [nil, "", "  ", [], ",", " , "] do
      assert BuildCheck.check(build(%{root_keys: keys})) == {:error, :no_root_key},
             inspect(keys)
    end
  end

  test "a customer build with a root key that is not a 32-byte base64 key is refused" do
    for keys <- [
          "not a key",
          Base.encode64(<<1::248>>),
          Base.encode64(<<1::264>>),
          "#{@root},#{@root}x",
          [@root, 42],
          [@root, ""],
          42
        ] do
      assert BuildCheck.check(build(%{root_keys: keys})) == {:error, :bad_root_key},
             inspect(keys)
    end
  end

  test "a customer build trusting the development key is refused" do
    assert BuildCheck.check(build(%{root_keys: @dev})) == {:error, :dev_root_key}
    assert BuildCheck.check(build(%{root_keys: "#{@root},#{@dev}"})) == {:error, :dev_root_key}
    assert BuildCheck.check(build(%{root_keys: [@root, @dev]})) == {:error, :dev_root_key}
  end

  test "the development key is compared as bytes, so another spelling of it is refused" do
    # Base64 ignores the last character's two spare bits, so one key has
    # four spellings. Change those bits and the key still decodes the same.
    <<head::binary-size(42), last, "=">> = @dev
    alphabet = ~c"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    index = Enum.find_index(alphabet, &(&1 == last))
    other = head <> <<Enum.at(alphabet, Bitwise.bxor(index, 1))>> <> "="

    assert Base.decode64!(other) == Base.decode64!(@dev)
    assert BuildCheck.check(build(%{root_keys: other})) == {:error, :dev_root_key}
  end

  test "check off answers first, and a bad key answers before the dev key" do
    assert BuildCheck.check(build(%{enforced?: false, root_keys: nil})) ==
             {:error, :licence_check_off}

    assert BuildCheck.check(build(%{enforced?: false, root_keys: @dev})) ==
             {:error, :licence_check_off}

    assert BuildCheck.check(build(%{root_keys: "bad,#{@dev}"})) == {:error, :bad_root_key}
  end

  test "a customer flag that is not false counts as a customer build" do
    assert BuildCheck.check(build(%{customer?: nil, enforced?: false})) ==
             {:error, :licence_check_off}
  end

  test "an app's malformed development key raises rather than passing every build" do
    assert_raise ArgumentError, fn -> BuildCheck.check(build(%{dev_keys: ["not a key"]})) end
  end
end
