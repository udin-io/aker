defmodule Mix.Tasks.Aker.SignTest do
  @moduledoc """
  `mix aker.sign` turns an install's activation request into a
  licence that install accepts, with key files kept outside the checkout,
  and prints no key material.
  """
  # Not async: the task prints through the process-wide Mix shell.
  use ExUnit.Case, async: false

  @moduletag :capture_log

  import Aker.TestSupport.Keys
  import Aker.TestSupport.Licences, only: [verify_opts: 2]

  alias Aker.LicenceFile
  alias Aker.Request
  alias Aker.SigningKey
  alias Mix.Tasks.Aker.Sign

  setup do
    # Outside the checkout: the task refuses a key inside the folder it runs in.
    dir = Path.join(System.tmp_dir!(), "aker_sign_#{System.unique_integer([:positive])}")
    File.mkdir_p!(dir)
    on_exit(fn -> File.rm_rf!(dir) end)

    seed = :crypto.strong_rand_bytes(32)
    root = Path.join(dir, "root.pem")
    File.write!(root, pem(seed))
    {:ok, root_key} = SigningKey.from_pem(pem(seed))

    install = install(Path.join(dir, "install"))

    {:ok, request} =
      Request.build(
        product: "acme_vision",
        product_version: "2.4.1",
        install_key: install.install_key,
        machine_id_hash: install.machine_id_hash
      )

    request_path = Path.join(dir, "request.json")
    File.write!(request_path, request)

    Mix.shell(Mix.Shell.Process)
    on_exit(fn -> Mix.shell(Mix.Shell.IO) end)

    %{
      dir: dir,
      root: root,
      seed: seed,
      root_public_key: Base.decode64!(SigningKey.public_key(root_key)),
      install: install,
      request: request_path
    }
  end

  defp printed do
    receive do
      {:mix_shell, _level, message} -> [IO.iodata_to_binary(message) | printed()]
    after
      0 -> []
    end
  end

  defp base(ctx, extra \\ []) do
    [
      ctx.request,
      "--product",
      "acme_vision",
      "--root-key",
      ctx.root,
      "--customer",
      "Acme",
      "--seats",
      "8",
      "--term",
      "monthly"
    ] ++ extra
  end

  defp verify(ctx, path, extra \\ []) do
    LicenceFile.verify(
      File.read!(path),
      verify_opts(ctx.install, Keyword.merge([root_keys: [ctx.root_public_key]], extra))
    )
  end

  test "the sign task signs a request from Aker.Request and the file verifies", ctx do
    Sign.run(base(ctx))

    out = Path.join(ctx.dir, "licence.json")
    assert {:ok, terms} = verify(ctx, out)
    assert terms.customer_name == "Acme"
    assert terms.seats == 8
    assert terms.serial == 1
    assert terms.features == []
    assert DateTime.diff(terms.term_end, terms.term_start, :day) == 30

    assert [output] = printed()
    assert output =~ "its root keys list #{Base.encode64(ctx.root_public_key)}."
    refute output =~ "PRIVATE KEY"
    refute output =~ Base.encode64(ctx.seed)
    refute output =~ File.read!(ctx.root) |> String.split("\n") |> Enum.at(1)
  end

  test "takes features, a working key, a serial, a yearly term and --out", ctx do
    working = Path.join(ctx.dir, "working.pem")
    File.write!(working, pem(:crypto.strong_rand_bytes(32)))
    out = Path.join(ctx.dir, "next.json")

    Sign.run(
      base(ctx, [
        "--features",
        "reports,export.csv",
        "--working-key",
        working,
        "--term",
        "yearly",
        "--serial",
        "2",
        "--key-id",
        "w2",
        "--out",
        out
      ])
    )

    assert {:ok, terms} = verify(ctx, out, stored_serial: 1)
    assert terms.features == ["reports", "export.csv"]

    Sign.run(base(ctx, ["--features", "", "--out", out, "--serial", "3"]))
    assert {:ok, %{features: []}} = verify(ctx, out, stored_serial: 2)
    assert terms.serial == 2
    assert terms.working_key_id == "w2"
    assert DateTime.diff(terms.term_end, terms.term_start, :day) == 365
  end

  test "a licence it signs is refused by an app that trusts another root", ctx do
    Sign.run(base(ctx))

    assert verify(ctx, Path.join(ctx.dir, "licence.json"),
             root_keys: [:crypto.strong_rand_bytes(32)]
           ) ==
             {:error, :unknown_root}
  end

  @tag :tmp_dir
  test "the sign task refuses a root key inside the checkout", ctx do
    # ExUnit makes `tmp_dir` under the checkout's own tmp/ folder.
    inside = Path.join(ctx.tmp_dir, "root.pem")
    File.cp!(ctx.root, inside)
    assert String.starts_with?(Path.expand(inside), File.cwd!())

    for key <- [inside, String.upcase(inside)] do
      assert_raise Mix.Error, ~r/keep it off the repository/, fn ->
        Sign.run(base(ctx) |> List.replace_at(4, key))
      end
    end

    refute File.exists?(Path.join(ctx.dir, "licence.json"))
    Sign.run(base(ctx))
    assert File.exists?(Path.join(ctx.dir, "licence.json"))
  end

  test "refuses a request that is not signed by the key it names", ctx do
    envelope = Jason.decode!(File.read!(ctx.request))
    File.write!(ctx.request, Jason.encode!(%{envelope | "signature" => Base.encode64("forged")}))

    assert_raise Mix.Error, ~r/is not a signed acme_vision activation request/, fn ->
      Sign.run(base(ctx))
    end
  end

  test "refuses a request for another product", ctx do
    assert_raise Mix.Error, ~r/is not a signed other_product activation request/, fn ->
      Sign.run(base(ctx) |> List.replace_at(2, "other_product"))
    end

    refute File.exists?(Path.join(ctx.dir, "licence.json"))
  end

  test "refuses values an app would refuse in the licence", ctx do
    for {extra, message} <- [
          {["--serial", "0"], ~r/--serial is 1 or more/},
          {["--moves", "-1"], ~r/--moves is 0 or more/},
          {["--key-id", String.duplicate("k", 65)], ~r/--key-id is 1 to 64 bytes/},
          {["--features", "Reports"], ~r/--features is at most 32 names/},
          {["--features", Enum.map_join(1..33, ",", &"f#{&1}")], ~r/--features is at most 32/},
          {["--features", "reports,,export"], ~r/--features is at most 32/},
          {["--term", "36501"], ~r/--term is at most 36500 days/}
        ] do
      assert_raise Mix.Error, message, fn -> Sign.run(base(ctx, extra)) end
    end

    long = List.replace_at(base(ctx), 6, String.duplicate("c", 401))
    assert_raise Mix.Error, ~r/--customer is 1 to 400 bytes/, fn -> Sign.run(long) end

    bad_product = List.replace_at(base(ctx), 2, "Acme Vision")
    assert_raise Mix.Error, ~r/--product is 1 to 64 characters/, fn -> Sign.run(bad_product) end

    refute File.exists?(Path.join(ctx.dir, "licence.json"))
  end

  test "refuses missing options and a bad term", ctx do
    assert_raise Mix.Error, ~r/usage/, fn ->
      Sign.run([ctx.request, "--root-key", ctx.root, "--customer", "A", "--seats", "1"])
    end

    assert_raise Mix.Error, ~r/usage/, fn ->
      Sign.run(base(ctx) |> List.delete_at(1) |> List.delete_at(1))
    end

    assert_raise Mix.Error, ~r/--term is monthly, yearly or a number of days/, fn ->
      Sign.run(base(ctx) |> List.replace_at(10, "0"))
    end
  end
end
