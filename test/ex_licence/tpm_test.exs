defmodule ExLicence.TpmTest do
  @moduledoc """
  The install key inside a TPM chip. The `:tpm` tests drive a real TPM 2.0
  simulator (swtpm) through tpm2-tools. `mix test` leaves them out; CI's
  `tpm` job runs `mix test --only tpm` on a runner with both installed.
  The rest run everywhere, against stand-in tools.
  """
  use ExUnit.Case, async: true

  alias ExLicence.InstallKey
  alias ExLicence.InstallKey.Software
  alias ExLicence.InstallKey.Tpm

  @moduletag :tmp_dir
  @moduletag :capture_log

  # SubjectPublicKeyInfo's fixed head for a P-256 key, as tpm2_readpublic
  # writes it with `-f der`.
  @spki_head_for_tests <<0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02,
                         0x01, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07, 0x03,
                         0x42, 0x00>>

  describe "which key an install uses" do
    setup %{tmp_dir: dir} do
      device = Path.join(dir, "tpmrm0")
      %{device: device, licence: Path.join(dir, "licence")}
    end

    test "a machine with no chip keeps its key in a file", ctx do
      assert {Software, _opts} = InstallKey.for_dir(ctx.licence, tpm_device: ctx.device)
    end

    test "a machine with a chip makes its key in the chip", ctx do
      File.write!(ctx.device, "")
      assert {Tpm, opts} = InstallKey.for_dir(ctx.licence, tpm_device: ctx.device)
      assert opts[:dir] == ctx.licence
    end

    test "a key made in a file stays in the file when a chip appears", ctx do
      {:ok, _public_key} = Software.ensure(dir: ctx.licence)
      File.write!(ctx.device, "")

      assert {Software, _opts} = InstallKey.for_dir(ctx.licence, tpm_device: ctx.device)
    end

    test "a key made in the chip stays the chip's when the chip is gone", ctx do
      File.mkdir_p!(Path.join(ctx.licence, "tpm_key"))
      File.write!(Path.join(ctx.licence, "tpm_key/key.pub"), "")

      assert {Tpm, opts} = InstallKey.for_dir(ctx.licence, tpm_device: ctx.device)
      # The tools talk to the device the choice read.
      assert opts[:tcti] == "device:" <> ctx.device
    end
  end

  describe "a chip that fails" do
    # Stand-in tpm2 tools: shell scripts that hang or fail.
    defp tools(dir, script) do
      tools = Path.join(dir, "tools")
      File.mkdir_p!(tools)

      for tool <-
            ~w(tpm2_createprimary tpm2_create tpm2_load tpm2_readpublic tpm2_sign tpm2_flushcontext) do
        path = Path.join(tools, tool)
        File.write!(path, "#!/bin/sh\n" <> script)
        File.chmod!(path, 0o755)
      end

      tools
    end

    test "a hung chip is stopped at the time limit, even one that ignores the stop", %{
      tmp_dir: dir
    } do
      # `trap '' TERM` ignores the polite stop, so only the kill ends it.
      # `exec` makes the hung program the one `timeout` signals: a child left
      # behind would hold the output open past the kill.
      opts = [
        dir: Path.join(dir, "licence"),
        tools: tools(dir, "trap '' TERM\nexec sleep 30\n"),
        timeout_s: 1
      ]

      {elapsed_us, answer} = :timer.tc(fn -> Tpm.ensure(opts) end)
      assert answer == {:error, :install_key_timeout}
      assert elapsed_us < 15_000_000
    end

    test "two first boots at once keep one key, and both answer it", %{tmp_dir: dir} do
      opts = [dir: Path.join(dir, "licence"), tools: fake_chip(dir)]

      answers =
        1..6
        |> Enum.map(fn _ -> Task.async(fn -> Tpm.ensure(opts) end) end)
        |> Enum.map(&Task.await(&1, 30_000))

      assert [{:ok, <<4, _::512>> = public_key}] = Enum.uniq(answers)
      assert Tpm.public_key(opts) == {:ok, public_key}
      assert File.ls!(opts[:dir]) == ["tpm_key"]
    end

    test "a relative licence folder names the same key from the tools' folder",
         %{tmp_dir: dir} do
      relative = Path.relative_to(Path.join(dir, "licence"), File.cwd!())
      opts = [dir: relative, tools: fake_chip(dir)]

      assert Path.type(relative) == :relative
      assert {:ok, <<4, _::512>> = public_key} = Tpm.ensure(opts)
      assert Tpm.public_key(opts) == {:ok, public_key}
    end

    test "a time limit of 0, which would mean no limit, is refused", %{tmp_dir: dir} do
      for limit <- [0, -1, 61, 1.5, "10"] do
        opts = [dir: Path.join(dir, "licence"), tools: fake_chip(dir), timeout_s: limit]
        assert Tpm.ensure(opts) == {:error, :install_key_missing}, inspect(limit)
      end

      assert {:ok, _key} =
               Tpm.ensure(dir: Path.join(dir, "licence"), tools: fake_chip(dir), timeout_s: 60)
    end

    test "a chip that refuses answers missing, and leaves no key behind", %{tmp_dir: dir} do
      opts = [dir: Path.join(dir, "licence"), tools: tools(dir, "echo 'no TPM' >&2; exit 1\n")]

      assert Tpm.ensure(opts) == {:error, :install_key_missing}
      refute Tpm.made_here?(opts[:dir])
    end

    test "a licence naming a chip key, on a machine whose chip is gone", %{tmp_dir: dir} do
      licence = Path.join(dir, "licence")
      File.mkdir_p!(Path.join(licence, "tpm_key"))
      File.write!(Path.join(licence, "tpm_key/key.pub"), "made by a chip")
      File.write!(Path.join(licence, "tpm_key/key.priv"), "made by a chip")

      opts = [dir: licence, tools: Path.join(dir, "no-tools")]
      assert Tpm.public_key(opts) == {:error, :install_key_missing}
      assert Tpm.sign("x", opts) == {:error, :install_key_missing}
    end
  end

  describe "a real chip" do
    @describetag :tpm

    setup %{tmp_dir: dir} do
      %{chip: swtpm(dir, "chip-a"), other_chip: swtpm(dir, "chip-b")}
    end

    test "makes the key, keeps its public half across restarts, and signs", ctx do
      opts = [dir: Path.join(ctx.tmp_dir, "licence"), tcti: ctx.chip.tcti]

      assert {:ok, <<4, _::512>> = public_key} = Tpm.ensure(opts)

      # The chip restarts on its own state, as a machine reboot does.
      restarted = restart(ctx.chip)
      opts = Keyword.put(opts, :tcti, restarted)

      assert Tpm.ensure(opts) == {:ok, public_key}
      assert Tpm.public_key(opts) == {:ok, public_key}

      assert {:ok, signature} = Tpm.sign("challenge", opts)
      assert InstallKey.verify(public_key, "challenge", signature)
      assert InstallKey.proves?({Tpm, opts}, public_key)
    end

    test "no file holds the private key: another chip cannot use the folder", ctx do
      dir = Path.join(ctx.tmp_dir, "licence")
      {:ok, _public_key} = Tpm.ensure(dir: dir, tcti: ctx.chip.tcti)

      assert File.ls!(dir) == ["tpm_key"]
      assert Enum.sort(File.ls!(Path.join(dir, "tpm_key"))) == ["key.priv", "key.pub"]

      # The same files on a copied disk, against another machine's chip.
      assert Tpm.public_key(dir: dir, tcti: ctx.other_chip.tcti) == {:error, :install_key_missing}

      assert Tpm.sign("challenge", dir: dir, tcti: ctx.other_chip.tcti) ==
               {:error, :install_key_missing}
    end
  end

  # A TPM 2.0 simulator on two free ports, stopped when the test ends.
  defp swtpm(_dir, name) do
    # swtpm splits its options at commas, and a test's own folder carries
    # the test's name, so the state lives in a folder with a plain name.
    state =
      Path.join(
        System.tmp_dir!(),
        "ex_licence-swtpm-#{name}-#{System.unique_integer([:positive])}"
      )

    File.mkdir_p!(state)
    on_exit(fn -> File.rm_rf(state) end)
    start_swtpm(state)
  end

  defp start_swtpm(state) do
    swtpm = System.find_executable("swtpm") || flunk("swtpm is not installed")
    port = free_port()

    port_ref =
      Port.open({:spawn_executable, swtpm}, [
        :binary,
        :exit_status,
        args: [
          "socket",
          "--tpm2",
          "--tpmstate",
          "dir=#{state}",
          "--server",
          "type=tcp,port=#{port}",
          "--ctrl",
          "type=tcp,port=#{port + 1}",
          "--flags",
          "not-need-init,startup-clear"
        ]
      ])

    {:os_pid, os_pid} = Port.info(port_ref, :os_pid)
    on_exit(fn -> System.cmd("kill", [Integer.to_string(os_pid)]) end)
    # The control channel, so the probe never takes the command channel.
    wait_for(port + 1)
    %{tcti: "swtpm:port=#{port}", state: state, os_pid: os_pid}
  end

  # Stops the simulator and starts it again on the same state.
  defp restart(chip) do
    {_out, 0} = System.cmd("kill", [Integer.to_string(chip.os_pid)])
    wait_gone(chip.os_pid)
    start_swtpm(chip.state).tcti
  end

  defp wait_gone(os_pid, tries \\ 50) do
    case System.cmd("kill", ["-0", Integer.to_string(os_pid)], stderr_to_stdout: true) do
      {_out, 0} when tries > 0 ->
        Process.sleep(100)
        wait_gone(os_pid, tries - 1)

      _gone ->
        :ok
    end
  end

  # Stand-in tpm2 tools that act as a chip would, enough for the files
  # the library writes: `create` makes a random point, `readpublic` hands it back.
  defp fake_chip(dir) do
    # Octal escapes: a POSIX `printf` reads no hex.
    head =
      for <<byte <- @spki_head_for_tests>>,
        into: "",
        do: "\\" <> String.pad_leading(Integer.to_string(byte, 8), 3, "0")

    tools = Path.join(dir, "fake-chip")
    File.mkdir_p!(tools)

    scripts = %{
      "tpm2_createprimary" => "touch primary.ctx\n",
      "tpm2_flushcontext" => "exit 0\n",
      "tpm2_create" => """
      while [ $# -gt 0 ]; do case "$1" in -u) pub="$2"; shift;; -r) priv="$2"; shift;; esac; shift; done
      { printf '\\004'; head -c 64 /dev/urandom; } > "$pub"
      cp "$pub" "$priv"
      sleep 0.2
      """,
      "tpm2_load" => """
      while [ $# -gt 0 ]; do case "$1" in -u) pub="$2"; shift;; -c) ctx="$2"; shift;; esac; shift; done
      cp "$pub" "$ctx"
      """,
      "tpm2_readpublic" => """
      while [ $# -gt 0 ]; do case "$1" in -c) ctx="$2"; shift;; -o) out="$2"; shift;; esac; shift; done
      { printf '#{head}'; cat "$ctx"; } > "$out"
      """
    }

    for {tool, body} <- scripts do
      path = Path.join(tools, tool)
      File.write!(path, "#!/bin/sh\n" <> body)
      File.chmod!(path, 0o755)
    end

    tools
  end

  # Two free ports in a row: swtpm takes the next one for its control
  # channel.
  defp free_port do
    port = 20_000 + :rand.uniform(30_000)

    if free?(port) and free?(port + 1), do: port, else: free_port()
  end

  defp free?(port) do
    case :gen_tcp.listen(port, reuseaddr: false) do
      {:ok, socket} -> :gen_tcp.close(socket) == :ok
      {:error, _taken} -> false
    end
  end

  defp wait_for(port, tries \\ 50) do
    case :gen_tcp.connect(~c"localhost", port, [], 100) do
      {:ok, socket} ->
        :gen_tcp.close(socket)

      {:error, _reason} when tries > 0 ->
        Process.sleep(100)
        wait_for(port, tries - 1)

      {:error, reason} ->
        flunk("swtpm did not start: #{inspect(reason)}")
    end
  end
end
