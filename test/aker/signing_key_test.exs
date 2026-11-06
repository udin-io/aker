defmodule Aker.SigningKeyTest do
  @moduledoc """
  How a private Ed25519 signing key is read and held: only the PEM block
  openssl writes, never from inside the checkout, and never printed.
  """
  use ExUnit.Case, async: true

  import Aker.TestSupport.Keys, only: [pem: 1]

  alias Aker.SigningKey

  @moduletag :tmp_dir

  setup %{tmp_dir: dir} do
    repo = Path.join(dir, "checkout")
    outside = Path.join(dir, "keys")
    File.mkdir_p!(Path.join(repo, "config"))
    File.mkdir_p!(outside)
    seed = :crypto.strong_rand_bytes(32)
    inside_key = Path.join(repo, "config/root.pem")
    outside_key = Path.join(outside, "root.pem")
    File.write!(inside_key, pem(seed))
    File.write!(outside_key, pem(seed))

    %{repo: repo, inside_key: inside_key, outside_key: outside_key, seed: seed}
  end

  test "reads the PEM file openssl writes, and its signature verifies", ctx do
    assert {:ok, key} = SigningKey.load(ctx.outside_key, ctx.repo)

    signature = SigningKey.sign(key, "manifest")
    public = Base.decode64!(SigningKey.public_key(key))
    assert byte_size(public) == 32
    assert :crypto.verify(:eddsa, :none, "manifest", signature, [public, :ed25519])
  end

  test "a signing key inside the checkout is refused, through a symlink and in another letter case",
       ctx do
    linked_key = Path.join(ctx.tmp_dir, "linked-key.pem")
    File.ln_s!(ctx.inside_key, linked_key)
    linked_checkout = Path.join(ctx.tmp_dir, "linked-checkout")
    File.ln_s!(ctx.repo, linked_checkout)

    for path <- [
          ctx.inside_key,
          Path.join(ctx.repo, "config/../config/root.pem"),
          linked_key,
          Path.join(linked_checkout, "config/root.pem"),
          String.upcase(ctx.inside_key),
          # The system follows the link before it applies the `..`.
          dotdot_through_link(ctx)
        ] do
      assert {:error, message} = SigningKey.load(path, ctx.repo), path
      assert message =~ "keep it off the repository"
    end

    assert {:ok, _key} = SigningKey.load(ctx.outside_key, ctx.repo)
  end

  test "a path through more than 40 links is refused", ctx do
    first = Path.join(ctx.tmp_dir, "hop-0")

    for n <- 0..40 do
      target = if n == 40, do: ctx.outside_key, else: Path.join(ctx.tmp_dir, "hop-#{n + 1}")
      File.ln_s!(target, Path.join(ctx.tmp_dir, "hop-#{n}"))
    end

    assert SigningKey.load(first, ctx.repo) ==
             {:error, "the key's path follows too many links"}

    # 20 links: under both this limit and the system's own.
    assert {:ok, _key} = SigningKey.load(Path.join(ctx.tmp_dir, "hop-21"), ctx.repo)
  end

  # `linked/../root.pem`, where `linked` points at a folder inside the
  # checkout: the file it opens is the checkout's `config/root.pem`.
  defp dotdot_through_link(ctx) do
    File.mkdir_p!(Path.join(ctx.repo, "config/deep"))
    link = Path.join(ctx.tmp_dir, "into-checkout")
    File.ln_s!(Path.join(ctx.repo, "config/deep"), link)
    Path.join(link, "../root.pem")
  end

  test "inspect of a signing key shows no key bytes", ctx do
    {:ok, key} = SigningKey.from_pem(pem(ctx.seed))
    shown = inspect(key, limit: :infinity, structs: true)

    assert shown == "#Aker.SigningKey<redacted>"
    refute shown =~ Base.encode64(ctx.seed)
    refute inspect({:error, key}) =~ inspect(ctx.seed)
  end

  test "text that is not an Ed25519 key in PEM form is refused with no echo", ctx do
    rsa =
      "-----BEGIN PRIVATE KEY-----\n" <>
        Base.encode64(:crypto.strong_rand_bytes(64)) <>
        "\n-----END PRIVATE KEY-----\n"

    for text <- [rsa, "", "secret words", pem(<<1, 2, 3>>), pem(ctx.seed) <> "x", nil] do
      assert SigningKey.from_pem(text) == :error
    end

    File.write!(ctx.outside_key, "hunter2 correct horse battery staple\n")
    assert {:error, message} = SigningKey.load(ctx.outside_key, ctx.repo)
    assert message == "the key file is not an Ed25519 private key in PEM form"

    assert {:error, "cannot read the key file: no such file or directory"} =
             SigningKey.load(Path.join(ctx.tmp_dir, "missing.pem"), ctx.repo)
  end
end
