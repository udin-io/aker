defmodule Mix.Tasks.Aker.CertifyTest do
  @moduledoc """
  `mix aker.certify` signs a working key's certificate with the root key,
  offline, and prints it on one line for a licensing server to hold. It
  never prints the working key.
  """
  # Not async: the task prints through the process-wide Mix shell.
  use ExUnit.Case, async: false

  @moduletag :capture_log

  import Aker.TestSupport.Keys

  alias Aker.Issuer
  alias Aker.LicenceFile
  alias Aker.Request
  alias Aker.SigningKey
  alias Mix.Tasks.Aker.Certify

  setup do
    # Outside the checkout: the task refuses a key inside the folder it runs in.
    dir = Path.join(System.tmp_dir!(), "aker_certify_#{System.unique_integer([:positive])}")
    File.mkdir_p!(dir)
    on_exit(fn -> File.rm_rf!(dir) end)

    root_seed = :crypto.strong_rand_bytes(32)
    working_seed = :crypto.strong_rand_bytes(32)
    root = Path.join(dir, "root.pem")
    working = Path.join(dir, "working.pem")
    File.write!(root, pem(root_seed))
    File.write!(working, pem(working_seed))
    {:ok, root_key} = SigningKey.from_pem(pem(root_seed))
    {:ok, working_key} = SigningKey.from_pem(pem(working_seed))

    Mix.shell(Mix.Shell.Process)
    on_exit(fn -> Mix.shell(Mix.Shell.IO) end)

    %{
      dir: dir,
      root: root,
      working: working,
      working_seed: working_seed,
      root_key: root_key,
      working_key: working_key
    }
  end

  defp printed do
    receive do
      {:mix_shell, _level, message} -> [IO.iodata_to_binary(message) | printed()]
    after
      0 -> []
    end
  end

  defp args(ctx, extra \\ []),
    do: ["--root-key", ctx.root, "--working-key", ctx.working, "--key-id", "w-2026-11"] ++ extra

  defp certificate_line(output) do
    output
    |> Enum.flat_map(&String.split(&1, "\n"))
    |> Enum.find_value(fn line ->
      case Issuer.decode_certificate(String.trim(line)) do
        {:ok, pair} -> pair
        :error -> nil
      end
    end)
  end

  test "prints a certificate an issue accepts, and never the working key", ctx do
    Certify.run(args(ctx))
    output = printed()
    text = Enum.join(output, "\n")

    assert %{} = certificate = certificate_line(output)
    assert text =~ "w-2026-11"
    assert text =~ SigningKey.public_key(ctx.root_key)
    refute text =~ "PRIVATE KEY"
    refute text =~ Base.encode64(ctx.working_seed)
    refute text =~ File.read!(ctx.working) |> String.split("\n") |> Enum.at(1)

    install = install(Path.join(ctx.dir, "install"))

    {:ok, request} =
      Request.build(
        product: "acme_vision",
        product_version: "2.4.1",
        install_key: install.install_key,
        machine_id_hash: install.machine_id_hash
      )

    root_public_key = Base.decode64!(SigningKey.public_key(ctx.root_key))

    assert {:ok, licence} =
             Issuer.issue(request,
               product: "acme_vision",
               working_key: ctx.working_key,
               certificate: certificate,
               root_keys: [root_public_key],
               customer: "Acme Logistics",
               seats: 4,
               term_days: 365
             )

    assert {:ok, terms} =
             LicenceFile.verify(licence,
               product: "acme_vision",
               root_keys: [root_public_key],
               install_key: install.install_key,
               machine_id_hash: install.machine_id_hash
             )

    assert terms.working_key_id == "w-2026-11"
  end

  test "--days and --not-before set the certificate's window", ctx do
    Certify.run(args(ctx, ["--days", "600", "--not-before", "2026-11-01T00:00:00Z"]))
    certificate = certificate_line(printed())

    fields = Jason.decode!(certificate.certificate)
    assert fields["not_before"] == "2026-11-01T00:00:00Z"
    assert fields["not_after"] == "2028-06-23T00:00:00Z"
    assert fields["key_id"] == "w-2026-11"
    assert fields["public_key"] == SigningKey.public_key(ctx.working_key)
  end

  test "--days defaults to 470", ctx do
    Certify.run(args(ctx, ["--not-before", "2026-11-01T00:00:00Z"]))
    fields = Jason.decode!(certificate_line(printed()).certificate)

    assert fields["not_after"] ==
             DateTime.to_iso8601(DateTime.add(~U[2026-11-01 00:00:00Z], 470, :day))
  end

  test "refuses --days outside 1 to 600", ctx do
    for days <- ["601", "0", "-1", "ten"] do
      assert_raise Mix.Error, ~r/--days is 1 to 600/, fn ->
        Certify.run(args(ctx, ["--days", days]))
      end
    end

    Certify.run(args(ctx, ["--days", "1"]))
    assert %{} = certificate_line(printed())
  end

  test "refuses a bad --not-before, a bad key id and missing options", ctx do
    assert_raise Mix.Error, ~r/--not-before/, fn ->
      Certify.run(args(ctx, ["--not-before", "next week"]))
    end

    assert_raise Mix.Error, ~r/--key-id is 1 to 64 bytes/, fn ->
      Certify.run([
        "--root-key",
        ctx.root,
        "--working-key",
        ctx.working,
        "--key-id",
        String.duplicate("k", 65)
      ])
    end

    assert_raise Mix.Error, ~r/usage/, fn ->
      Certify.run(["--root-key", ctx.root, "--key-id", "w"])
    end

    assert printed() == []
  end

  test "refuses the root key as its own working key, and a date past year 9999", ctx do
    assert_raise Mix.Error, ~r/--working-key is the root key/, fn ->
      Certify.run(["--root-key", ctx.root, "--working-key", ctx.root, "--key-id", "w"])
    end

    assert_raise Mix.Error, ~r/ends after the year 9999/, fn ->
      Certify.run(args(ctx, ["--not-before", "9999-12-01T00:00:00Z", "--days", "600"]))
    end

    assert printed() == []
  end

  @tag :tmp_dir
  test "refuses a key inside the checkout", ctx do
    # ExUnit makes `tmp_dir` under the checkout's own tmp/ folder.
    inside = Path.join(ctx.tmp_dir, "key.pem")
    File.cp!(ctx.root, inside)
    assert String.starts_with?(Path.expand(inside), File.cwd!())

    assert_raise Mix.Error, ~r/keep it off the repository/, fn ->
      Certify.run(["--root-key", inside, "--working-key", ctx.working, "--key-id", "w"])
    end

    assert_raise Mix.Error, ~r/keep it off the repository/, fn ->
      Certify.run(["--root-key", ctx.root, "--working-key", inside, "--key-id", "w"])
    end

    assert printed() == []
  end
end
