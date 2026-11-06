defmodule Aker.RequestTest do
  @moduledoc """
  The activation request: it names the product and version the app passes,
  carries the install key and machine id, and verifies only when the key
  it names signed it, for the product the reader expects.
  """
  use ExUnit.Case, async: true

  import Aker.TestSupport.Keys

  alias Aker.InstallKey.Software
  alias Aker.Request

  @moduletag :tmp_dir

  defp build(install, extra \\ []) do
    [
      product: "acme_vision",
      product_version: "2.4.1",
      install_key: install.install_key,
      machine_id_hash: install.machine_id_hash
    ]
    |> Keyword.merge(extra)
    |> Request.build()
  end

  defp fields(bytes),
    do: bytes |> Jason.decode!() |> Map.fetch!("request") |> Base.decode64!() |> Jason.decode!()

  # A request whose fields are `fields`, signed by `install`'s key.
  defp signed(install, fields) do
    {module, opts} = install.install_key
    request = Jason.encode!(fields)
    {:ok, signature} = module.sign(request, opts)
    Jason.encode!(%{"request" => Base.encode64(request), "signature" => Base.encode64(signature)})
  end

  test "carries the install key and machine id, signed by that key", %{tmp_dir: dir} do
    install = install(dir)
    {:ok, bytes} = build(install)

    assert Request.verify(bytes, product: "acme_vision") ==
             {:ok,
              %{install_public_key: install.public_key, machine_id_hash: install.machine_id_hash}}

    request = fields(bytes)
    assert request["install_key_kind"] == "software"
    assert byte_size(Base.decode64!(request["nonce"])) == 16
  end

  test "a request names the product and version the app passes", %{tmp_dir: dir} do
    {:ok, bytes} = build(install(dir))
    request = fields(bytes)

    assert request["product"] == "acme_vision"
    assert request["product_version"] == "2.4.1"
    refute Map.has_key?(request, "eagle_version")
  end

  test "a request for another product does not verify", %{tmp_dir: dir} do
    {:ok, bytes} = build(install(dir))

    assert Request.verify(bytes, product: "other_product") == {:error, :bad_request}
    assert {:ok, _fields} = Request.verify(bytes, product: "acme_vision")
  end

  test "a request signed by another key does not verify", %{tmp_dir: dir} do
    install = install(dir)
    other = install(Path.join(dir, "other"))
    {:ok, bytes} = build(install)
    request = Jason.decode!(bytes)["request"] |> Base.decode64!()
    {module, opts} = other.install_key
    {:ok, signature} = module.sign(request, opts)

    forged =
      Jason.encode!(%{
        "request" => Base.encode64(request),
        "signature" => Base.encode64(signature)
      })

    assert Request.verify(forged, product: "acme_vision") == {:error, :bad_request}
    assert {:ok, _fields} = Request.verify(bytes, product: "acme_vision")
  end

  test "a public key off the curve does not verify and does not raise", %{tmp_dir: dir} do
    install = install(dir)
    {:ok, bytes} = build(install)

    off_curve =
      bytes
      |> fields()
      |> Map.put("install_public_key", Base.encode64(<<4, 0::512>>))

    assert Request.verify(signed(install, off_curve), product: "acme_vision") ==
             {:error, :bad_request}

    assert {:ok, _fields} = Request.verify(signed(install, fields(bytes)), product: "acme_vision")
  end

  test "refuses a request whose fields changed after it was signed", %{tmp_dir: dir} do
    install = install(dir)
    {:ok, bytes} = build(install)
    envelope = Jason.decode!(bytes)
    forged = bytes |> fields() |> Map.put("machine_id_hash", String.duplicate("0", 64))

    assert Request.verify(
             Jason.encode!(%{envelope | "request" => Base.encode64(Jason.encode!(forged))}),
             product: "acme_vision"
           ) == {:error, :bad_request}

    assert Request.verify("not json", product: "acme_vision") == {:error, :bad_request}
  end

  test "a request over 8 KB does not verify", %{tmp_dir: dir} do
    install = install(dir)
    {:ok, bytes} = build(install)
    # JSON allows whitespace after the object, so padding keeps it valid.
    at_cap = bytes <> String.duplicate(" ", Request.max_bytes() - byte_size(bytes))

    assert byte_size(at_cap) == 8 * 1024
    assert {:ok, _fields} = Request.verify(at_cap, product: "acme_vision")
    assert Request.verify(at_cap <> " ", product: "acme_vision") == {:error, :bad_request}
  end

  test "refuses a signed request whose machine id hash is not a SHA-256", %{tmp_dir: dir} do
    install = install(dir)
    {:ok, bytes} = build(install)
    forged = bytes |> fields() |> Map.put("machine_id_hash", "host-1")

    assert Request.verify(signed(install, forged), product: "acme_vision") ==
             {:error, :bad_request}

    assert {:ok, _fields} = Request.verify(signed(install, fields(bytes)), product: "acme_vision")
  end

  test "build refuses what verify would refuse: a bad machine id hash or version",
       %{tmp_dir: dir} do
    install = install(dir)

    for hash <- ["host-1", String.duplicate("A", 64), String.duplicate("a", 65), nil] do
      assert build(install, machine_id_hash: hash) == {:error, :bad_machine_id_hash}
    end

    for version <- ["", "1.0 beta", String.duplicate("1", 65), 2, nil] do
      assert build(install, product_version: version) == {:error, :bad_product_version}
    end

    assert {:ok, _bytes} = build(install, product_version: "1.0.0-rc.1+build.5")
  end

  test "a product name with a character outside a-z 0-9 _ - is refused", %{tmp_dir: dir} do
    install = install(dir)

    for bad <- [
          "Acme",
          "acme vision",
          "acme.vision",
          "acme/vision",
          "",
          String.duplicate("a", 65)
        ] do
      assert build(install, product: bad) == {:error, :bad_product}, inspect(bad)
      refute Request.product?(bad)
    end

    for good <- ["a", "acme-vision_2", String.duplicate("a", 64)] do
      assert {:ok, _bytes} = build(install, product: good), inspect(good)
    end
  end

  test "answers the key's error when the install has no key", %{tmp_dir: dir} do
    assert Request.build(
             product: "acme_vision",
             product_version: "1.0.0",
             install_key: {Software, dir: Path.join(dir, "none")},
             machine_id_hash: String.duplicate("a", 64)
           ) == {:error, :install_key_missing}
  end
end
