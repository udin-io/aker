defmodule ExLicence.MachineIdTest do
  @moduledoc """
  The machine id hash a licence names: the SHA-256 of the trimmed id in
  the file the app passes.
  """
  use ExUnit.Case, async: true

  alias ExLicence.MachineId

  @moduletag :tmp_dir

  test "hashes the trimmed id, so a trailing newline does not change it", %{tmp_dir: dir} do
    a = Path.join(dir, "a")
    b = Path.join(dir, "b")
    File.write!(a, "4f1c0d9a2b3e4f5061728394a5b6c7d8\n")
    File.write!(b, "4f1c0d9a2b3e4f5061728394a5b6c7d8")

    expected =
      :crypto.hash(:sha256, "4f1c0d9a2b3e4f5061728394a5b6c7d8") |> Base.encode16(case: :lower)

    assert MachineId.hash(a) == {:ok, expected}
    assert MachineId.hash(b) == {:ok, expected}
  end

  test "answers missing for an absent or empty file", %{tmp_dir: dir} do
    empty = Path.join(dir, "empty")
    File.write!(empty, "\n")

    assert MachineId.hash(Path.join(dir, "none")) == {:error, :machine_id_missing}
    assert MachineId.hash(empty) == {:error, :machine_id_missing}
  end

  test "an id over 256 bytes is not a machine id, and 256 bytes is", %{tmp_dir: dir} do
    long = Path.join(dir, "long")
    edge = Path.join(dir, "edge")
    File.write!(long, String.duplicate("a", 257))
    File.write!(edge, String.duplicate("a", 256))

    assert MachineId.hash(long) == {:error, :machine_id_missing}
    assert {:ok, <<_::binary-size(64)>>} = MachineId.hash(edge)
  end

  test "a large file or an endless device is not a machine id, and costs no memory",
       %{tmp_dir: dir} do
    big = Path.join(dir, "big")
    File.write!(big, String.duplicate("a", 10_000_000))

    assert MachineId.hash(big) == {:error, :machine_id_missing}
    assert MachineId.hash("/dev/zero") == {:error, :machine_id_missing}
  end

  test "a file that runs past the cap is refused, even when its start trims to an id",
       %{tmp_dir: dir} do
    padded = Path.join(dir, "padded")

    File.write!(
      padded,
      "4f1c0d9a2b3e4f5061728394a5b6c7d8" <> String.duplicate("\n", 230) <> "more"
    )

    assert MachineId.hash(padded) == {:error, :machine_id_missing}
  end
end
