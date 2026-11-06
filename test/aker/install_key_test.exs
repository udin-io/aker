defmodule Aker.InstallKeyTest do
  @moduledoc """
  The software install key is a 0600 file made once, which keeps
  the same public key across restarts and signs what verifies against it.
  """
  use ExUnit.Case, async: true

  alias Aker.InstallKey
  alias Aker.InstallKey.Software

  @moduletag :tmp_dir

  setup %{tmp_dir: dir}, do: %{opts: [dir: Path.join(dir, "licence")]}

  test "makes the key once, mode 0600 in a 0700 folder, and keeps it", %{opts: opts} do
    assert Software.public_key(opts) == {:error, :install_key_missing}
    assert {:ok, <<4, _::512>> = public_key} = Software.ensure(opts)

    assert File.stat!(Software.path(opts)).mode |> Bitwise.band(0o777) == 0o600
    assert File.stat!(opts[:dir]).mode |> Bitwise.band(0o777) == 0o700

    # A restart reads the same file: the same key, and no second file.
    assert Software.ensure(opts) == {:ok, public_key}
    assert Software.public_key(opts) == {:ok, public_key}
    assert File.ls!(opts[:dir]) == ["install_key.pem"]
  end

  test "the install key file is mode 0600", %{opts: opts} do
    {:ok, _public_key} = Software.ensure(opts)

    assert File.stat!(Software.path(opts)).mode |> Bitwise.band(0o777) == 0o600
  end

  test "two first boots at once keep one key, and both answer it", %{opts: opts} do
    answers =
      1..8
      |> Enum.map(fn _ -> Task.async(fn -> Software.ensure(opts) end) end)
      |> Enum.map(&Task.await/1)

    assert [{:ok, public_key}] = Enum.uniq(answers)
    assert Software.public_key(opts) == {:ok, public_key}
    assert File.ls!(opts[:dir]) == ["install_key.pem"]
  end

  test "keeps the mode of a folder the operator made", %{opts: opts} do
    File.mkdir_p!(opts[:dir])
    File.chmod!(opts[:dir], 0o750)

    assert {:ok, _public_key} = Software.ensure(opts)
    assert File.stat!(opts[:dir]).mode |> Bitwise.band(0o777) == 0o750
    assert File.stat!(Software.path(opts)).mode |> Bitwise.band(0o777) == 0o600
  end

  test "signs what verifies against its public key, and nothing else", %{opts: opts} do
    {:ok, public_key} = Software.ensure(opts)
    {:ok, signature} = Software.sign("challenge", opts)

    assert InstallKey.verify(public_key, "challenge", signature)
    refute InstallKey.verify(public_key, "another", signature)
    assert InstallKey.proves?({Software, opts}, public_key)

    other = [dir: opts[:dir] <> "-other"]
    {:ok, other_public_key} = Software.ensure(other)
    refute InstallKey.proves?({Software, opts}, other_public_key)
  end

  test "refuses a signature on a point off the curve without raising", %{opts: opts} do
    {:ok, public_key} = Software.ensure(opts)
    {:ok, signature} = Software.sign("challenge", opts)

    assert InstallKey.point?(public_key)
    refute InstallKey.point?(<<4, 0::512>>)
    refute InstallKey.verify(<<4, 0::512>>, "challenge", signature)
    refute InstallKey.verify(public_key, "challenge", "forged")
  end

  test "refuses a key file whose public half was edited", %{opts: opts} do
    {:ok, _public_key} = Software.ensure(opts)

    [body] =
      Regex.run(~r/-----\n(.*)\n-----END/s, File.read!(Software.path(opts)),
        capture: :all_but_first
      )

    <<head::binary-size(56), _public::binary-size(65)>> = Base.decode64!(body)
    {:ok, other} = Software.ensure(dir: opts[:dir] <> "-other")
    edited = Base.encode64(head <> other)

    File.write!(
      Software.path(opts),
      "-----BEGIN EC PRIVATE KEY-----\n#{edited}\n-----END EC PRIVATE KEY-----\n"
    )

    assert Software.public_key(opts) == {:error, :install_key_unreadable}
  end

  test "refuses a key file that is not a P-256 key", %{opts: opts} do
    File.mkdir_p!(opts[:dir])

    File.write!(
      Software.path(opts),
      "-----BEGIN EC PRIVATE KEY-----\nAAAA\n-----END EC PRIVATE KEY-----\n"
    )

    assert Software.public_key(opts) == {:error, :install_key_unreadable}
    assert Software.sign("x", opts) == {:error, :install_key_unreadable}
    # A broken key is never replaced by a new one: the licence names the old.
    assert Software.ensure(opts) == {:error, :install_key_unreadable}

    p384 = :public_key.generate_key({:namedCurve, :secp384r1})

    File.write!(
      Software.path(opts),
      :public_key.pem_encode([:public_key.pem_entry_encode(:ECPrivateKey, p384)])
    )

    assert Software.public_key(opts) == {:error, :install_key_unreadable}
  end

  test "answers an error, not a crash, for a folder it cannot write", %{tmp_dir: dir} do
    blocker = Path.join(dir, "file")
    File.write!(blocker, "")

    assert Software.ensure(dir: Path.join(blocker, "licence")) ==
             {:error, :install_key_unwritable}
  end
end
