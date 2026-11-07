defmodule Aker.IssuerTest do
  @moduledoc """
  A licensing server signs with a working key the root certified offline:
  it holds the working key and its certificate, never the root key. The
  issuer refuses a certificate no trusted root signed, one for another
  key, and a term that ends after the certificate does.
  """
  use ExUnit.Case, async: true

  import Aker.TestSupport.Keys

  alias Aker.Issuer
  alias Aker.LicenceFile
  alias Aker.Request
  alias Aker.SigningKey

  @moduletag :tmp_dir
  @moduletag :capture_log

  setup %{tmp_dir: dir} do
    root_key = new_key()
    working_key = new_key()
    now = DateTime.truncate(DateTime.utc_now(), :second)
    install = install(Path.join(dir, "install"))

    {:ok, request} =
      Request.build(
        product: "acme_vision",
        product_version: "2.4.1",
        install_key: install.install_key,
        machine_id_hash: install.machine_id_hash
      )

    certificate =
      Issuer.certificate(root_key, working_key,
        key_id: "w-2026-11",
        not_before: DateTime.add(now, -1, :day),
        not_after: DateTime.add(now, 470, :day)
      )

    %{
      root_key: root_key,
      root_public_key: raw(root_key),
      working_key: working_key,
      certificate: certificate,
      not_after: DateTime.add(now, 470, :day),
      now: now,
      install: install,
      request: request
    }
  end

  defp raw(key), do: Base.decode64!(SigningKey.public_key(key))

  defp certified(ctx, extra \\ []) do
    Keyword.merge(
      [
        product: "acme_vision",
        working_key: ctx.working_key,
        certificate: ctx.certificate,
        root_keys: [ctx.root_public_key],
        customer: "Acme Logistics",
        seats: 10,
        term_days: 30,
        now: ctx.now
      ],
      extra
    )
  end

  defp verify(ctx, licence, extra \\ []) do
    LicenceFile.verify(
      licence,
      Keyword.merge(
        [
          product: "acme_vision",
          root_keys: [ctx.root_public_key],
          install_key: ctx.install.install_key,
          machine_id_hash: ctx.install.machine_id_hash,
          now: DateTime.add(ctx.now, 1, :hour)
        ],
        extra
      )
    )
  end

  test "a licence issued with a certificate verifies for that install and root", ctx do
    assert {:ok, licence} = Issuer.issue(ctx.request, certified(ctx))
    assert {:ok, terms} = verify(ctx, licence)
    assert terms.working_key_id == "w-2026-11"
    assert terms.customer_name == "Acme Logistics"
    assert terms.seats == 10

    assert verify(ctx, licence, root_keys: [raw(new_key())]) == {:error, :unknown_root}
  end

  test "refuses a certificate no trusted root signed", ctx do
    assert Issuer.issue(ctx.request, certified(ctx, root_keys: [raw(new_key())])) ==
             {:error, {:invalid, :certificate}}

    assert Issuer.issue(ctx.request, certified(ctx, root_keys: [])) ==
             {:error, {:invalid, :certificate}}

    assert {:ok, _licence} =
             Issuer.issue(
               ctx.request,
               certified(ctx, root_keys: [raw(new_key()), ctx.root_public_key])
             )
  end

  test "refuses a certificate for another working key", ctx do
    assert Issuer.issue(ctx.request, certified(ctx, working_key: new_key())) ==
             {:error, {:invalid, :certificate}}

    assert {:ok, _licence} = Issuer.issue(ctx.request, certified(ctx))
  end

  test "refuses a certificate that is not in date now", ctx do
    assert Issuer.issue(ctx.request, certified(ctx, now: DateTime.add(ctx.now, 471, :day))) ==
             {:error, {:invalid, :certificate}}

    assert Issuer.issue(ctx.request, certified(ctx, now: DateTime.add(ctx.now, -2, :day))) ==
             {:error, {:invalid, :certificate}}
  end

  test "refuses a certificate whose bytes changed after the root signed it", ctx do
    forged = %{ctx.certificate | certificate: ctx.certificate.certificate <> " "}

    assert Issuer.issue(ctx.request, certified(ctx, certificate: forged)) ==
             {:error, {:invalid, :certificate}}
  end

  test "a term ending one second after the certificate is refused, at its end accepted",
       ctx do
    start = DateTime.add(ctx.now, -1, :hour)

    assert Issuer.issue(
             ctx.request,
             certified(ctx,
               term_days: nil,
               term_start: start,
               term_end: DateTime.add(ctx.not_after, 1, :second)
             )
             |> Keyword.delete(:term_days)
           ) == {:error, {:invalid, :term_end}}

    assert {:ok, _licence} =
             Issuer.issue(
               ctx.request,
               certified(ctx, term_start: start, term_end: ctx.not_after)
               |> Keyword.delete(:term_days)
             )

    assert Issuer.issue(ctx.request, certified(ctx, term_days: 472)) ==
             {:error, {:invalid, :term_end}}
  end

  test "the licence id and exact term appear in the verified terms as passed", ctx do
    start = DateTime.add(ctx.now, -1, :hour)
    term_end = DateTime.add(start, 365, :day)

    opts =
      certified(ctx, licence_id: "lic-0042", serial: 3, term_start: start, term_end: term_end)
      |> Keyword.delete(:term_days)

    assert {:ok, licence} = Issuer.issue(ctx.request, opts)
    assert {:ok, terms} = verify(ctx, licence)
    assert terms.licence_id == "lic-0042"
    assert terms.serial == 3
    assert terms.term_start == start
    assert terms.term_end == term_end
  end

  test "a licence id outside 1 to 64 bytes is refused", ctx do
    for id <- ["", String.duplicate("a", 65), 42] do
      assert Issuer.issue(ctx.request, certified(ctx, licence_id: id)) ==
               {:error, {:invalid, :licence_id}}
    end

    assert {:ok, _licence} =
             Issuer.issue(ctx.request, certified(ctx, licence_id: String.duplicate("a", 64)))
  end

  test "a licence id or customer that is not UTF-8 is refused, not raised", ctx do
    assert Issuer.issue(ctx.request, certified(ctx, licence_id: <<0xFF>>)) ==
             {:error, {:invalid, :licence_id}}

    assert Issuer.issue(ctx.request, certified(ctx, customer: <<0xFF>>)) ==
             {:error, {:invalid, :customer}}

    assert {:ok, _licence} = Issuer.issue(ctx.request, certified(ctx, customer: "مؤسسة أكمي"))
  end

  test "a root-signed certificate too long for a licence file is refused", ctx do
    padded =
      Jason.encode!(%{
        "purpose" => LicenceFile.certificate_purpose(),
        "public_key" => SigningKey.public_key(ctx.working_key),
        "key_id" => "w-2026-11",
        "not_before" => DateTime.to_iso8601(DateTime.add(ctx.now, -1, :day)),
        "not_after" => DateTime.to_iso8601(ctx.not_after),
        "note" => String.duplicate("x", 1100)
      })

    long = %{certificate: padded, certificate_signature: SigningKey.sign(ctx.root_key, padded)}

    assert Issuer.issue(ctx.request, certified(ctx, certificate: long)) ==
             {:error, {:invalid, :certificate}}
  end

  test "both term forms, or a term that ends before it starts, are refused", ctx do
    start = DateTime.add(ctx.now, -1, :hour)

    assert Issuer.issue(
             ctx.request,
             certified(ctx, term_start: start, term_end: DateTime.add(start, 1, :day))
           ) == {:error, {:invalid, :term}}

    for {from, to} <- [{start, start}, {start, DateTime.add(start, -1, :second)}, {start, nil}] do
      opts =
        certified(ctx, term_start: from, term_end: to) |> Keyword.delete(:term_days)

      assert Issuer.issue(ctx.request, opts) == {:error, {:invalid, :term}}
    end
  end

  test "a key id that differs from the certificate's is refused", ctx do
    assert Issuer.issue(ctx.request, certified(ctx, key_id: "other")) ==
             {:error, {:invalid, :key_id}}

    assert {:ok, _licence} = Issuer.issue(ctx.request, certified(ctx, key_id: "w-2026-11"))
  end

  test "the root key together with a certificate is refused, and so is neither", ctx do
    assert Issuer.issue(ctx.request, certified(ctx, root_key: ctx.root_key)) ==
             {:error, {:invalid, :certificate}}

    neither = certified(ctx) |> Keyword.drop([:certificate, :root_keys])
    assert Issuer.issue(ctx.request, neither) == {:error, {:invalid, :certificate}}
  end

  test "encode_certificate then decode_certificate gives back the same pair", ctx do
    encoded = Issuer.encode_certificate(ctx.certificate)

    refute encoded =~ "\n"
    assert byte_size(encoded) <= 2048
    assert Issuer.decode_certificate(encoded) == {:ok, ctx.certificate}
  end

  test "decode_certificate refuses an input over 2 KB and other shapes", ctx do
    encoded = Issuer.encode_certificate(ctx.certificate)
    at_cap = encoded <> String.duplicate(" ", 2048 - byte_size(encoded))

    assert {:ok, _pair} = Issuer.decode_certificate(at_cap)
    assert Issuer.decode_certificate(at_cap <> " ") == :error

    for bad <- [
          "not json",
          "[]",
          Jason.encode!(%{"certificate" => "@@", "certificate_signature" => "AA=="}),
          Jason.encode!(%{"certificate" => Base.encode64("{}")}),
          Jason.encode!(%{
            "certificate" => Base.encode64("{}"),
            "certificate_signature" => Base.encode64("short")
          }),
          nil
        ] do
      assert Issuer.decode_certificate(bad) == :error
    end
  end

  test "the root key path mix aker.sign takes still signs a licence", ctx do
    opts =
      certified(ctx, root_key: ctx.root_key)
      |> Keyword.drop([:certificate, :root_keys])

    assert {:ok, licence} = Issuer.issue(ctx.request, opts)
    assert {:ok, terms} = verify(ctx, licence)
    assert terms.working_key_id == "dev"
  end
end
