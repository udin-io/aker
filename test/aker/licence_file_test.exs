defmodule Aker.LicenceFileTest do
  @moduledoc """
  An app accepts a licence only when every signature and field in it
  holds for this install. Each refusal test changes one field of a licence
  the control test accepts, and asserts the check that refuses it.
  """
  # Not async: the log test reads the shared log handler.
  use ExUnit.Case, async: false

  import ExUnit.CaptureLog
  import Aker.TestSupport.Keys
  import Aker.TestSupport.Licences

  alias Aker.InstallKey.Software
  alias Aker.Issuer
  alias Aker.LicenceFile
  alias Aker.Request
  alias Aker.Terms

  @moduletag :tmp_dir
  @moduletag :capture_log

  setup %{tmp_dir: dir} do
    %{install: install(dir)}
  end

  defp verify(install, bytes, extra \\ []),
    do: LicenceFile.verify(bytes, verify_opts(install, extra))

  test "accepts a licence issued from this install's activation request", %{install: install} do
    {:ok, request} =
      Request.build(
        product: product(),
        product_version: "2.4.1",
        install_key: install.install_key,
        machine_id_hash: install.machine_id_hash
      )

    {:ok, bytes} =
      Issuer.issue(request,
        product: product(),
        root_key: root_key(),
        working_key: new_key(),
        customer: "Acme Logistics",
        seats: 12,
        term_days: 30
      )

    assert {:ok, %Terms{} = terms} = verify(install, bytes)
    assert terms.customer_name == "Acme Logistics"
    assert terms.seats == 12
    assert terms.moves_per_term == 20
    assert terms.install_public_key == install.public_key
    assert terms.machine_id_hash == install.machine_id_hash
    assert DateTime.diff(terms.term_end, terms.term_start, :day) == 30
  end

  test "accepts the test helper's licence, the control for every refusal below",
       %{install: install} do
    assert {:ok, %Terms{serial: 1}} = verify(install, licence(install))
  end

  describe "the envelope, checked before anything is decoded" do
    test "refuses a file over 64 KB", %{install: install} do
      envelope = Jason.decode!(licence(install))
      padded = Jason.encode!(envelope) <> String.duplicate(" ", 64 * 1024)

      assert verify(install, padded) == {:error, :bad_envelope}
      # The same file without the padding is accepted.
      assert {:ok, _terms} = verify(install, Jason.encode!(envelope))
    end

    test "refuses a field of the wrong length", %{install: install} do
      envelope = Jason.decode!(licence(install))

      for {field, value} <- [
            {"signature", String.slice(envelope["signature"], 0, 87)},
            {"certificate_signature", envelope["certificate_signature"] <> "A"},
            {"licence", String.duplicate("A", 5468)},
            {"certificate", ""}
          ] do
        assert verify(install, Jason.encode!(Map.put(envelope, field, value))) ==
                 {:error, :bad_envelope},
               field
      end
    end

    test "refuses a missing, extra or non-text field, and a file that is not JSON",
         %{install: install} do
      envelope = Jason.decode!(licence(install))

      assert verify(install, Jason.encode!(Map.delete(envelope, "signature"))) ==
               {:error, :bad_envelope}

      assert verify(install, Jason.encode!(Map.put(envelope, "note", "x"))) ==
               {:error, :bad_envelope}

      assert verify(install, Jason.encode!(Map.put(envelope, "seats", 99))) ==
               {:error, :bad_envelope}

      assert verify(install, Jason.encode!(Map.put(envelope, "licence", 1))) ==
               {:error, :bad_envelope}

      assert verify(install, "not json") == {:error, :bad_envelope}
      assert verify(install, Jason.encode!([envelope])) == {:error, :bad_envelope}
    end

    test "refuses a field that is not base64", %{install: install} do
      envelope = Jason.decode!(licence(install))
      bad = "!" <> String.slice(envelope["signature"], 1..-1//1)

      assert verify(install, Jason.encode!(Map.put(envelope, "signature", bad))) ==
               {:error, :bad_envelope}
    end
  end

  describe "a byte changed in each part" do
    for {field, refusal} <- [
          {"licence", :bad_signature},
          {"signature", :bad_signature},
          {"certificate", :unknown_root},
          {"certificate_signature", :unknown_root}
        ] do
      test "in #{field} is refused as #{refusal}", %{install: install} do
        envelope = Jason.decode!(licence(install))
        <<first, rest::binary>> = Base.decode64!(envelope[unquote(field)])
        changed = Base.encode64(<<Bitwise.bxor(first, 1), rest::binary>>)

        assert verify(install, Jason.encode!(Map.put(envelope, unquote(field), changed))) ==
                 {:error, unquote(refusal)}
      end
    end
  end

  describe "the signatures" do
    test "refuses a certificate no trusted root key signed", %{install: install} do
      assert verify(install, licence(install, root_key: new_key())) == {:error, :unknown_root}
    end

    test "refuses a licence another key signed", %{install: install} do
      assert verify(install, licence(install, signing_key: new_key())) ==
               {:error, :bad_signature}
    end

    test "refuses a certificate the root signed with malformed fields", %{install: install} do
      assert verify(install, licence(install, key_id: "")) == {:error, :bad_certificate}
    end

    test "refuses other JSON the root signed, without the certificate's purpose",
         %{install: install} do
      working_key = new_key()
      now = DateTime.utc_now()

      for purpose <- [nil, "plugin-signing"] do
        bytes =
          %{
            "public_key" => Aker.SigningKey.public_key(working_key),
            "key_id" => "test-1",
            "not_before" => DateTime.to_iso8601(DateTime.add(now, -1, :day)),
            "not_after" => DateTime.to_iso8601(DateTime.add(now, 30, :day))
          }
          |> then(&if(purpose, do: Map.put(&1, "purpose", purpose), else: &1))
          |> Jason.encode!()

        certificate = %{
          certificate: bytes,
          certificate_signature: Aker.SigningKey.sign(root_key(), bytes)
        }

        fields =
          licence(install)
          |> Jason.decode!()
          |> Map.fetch!("licence")
          |> Base.decode64!()
          |> Jason.decode!()

        assert verify(install, Issuer.sign(fields, working_key, certificate)) ==
                 {:error, :bad_certificate}
      end
    end

    test "refuses a signed licence with malformed fields", %{install: install} do
      assert verify(install, licence(install, fields: %{"seats" => -1})) ==
               {:error, :bad_licence}

      assert verify(
               install,
               licence(install, fields: %{"term_end" => "2026-12-01T00:00:00+02:00"})
             ) ==
               {:error, :bad_licence}

      assert verify(install, licence(install, fields: %{"install_public_key" => "AAAA"})) ==
               {:error, :bad_licence}
    end

    test "refuses a licence naming another working key id", %{install: install} do
      assert verify(install, licence(install, fields: %{"working_key_id" => "other"})) ==
               {:error, :wrong_working_key}
    end
  end

  describe "the certificate's dates" do
    test "refuses a certificate that ended before now", %{install: install} do
      now = DateTime.utc_now()

      bytes =
        licence(install,
          not_before: DateTime.add(now, -10, :day),
          not_after: DateTime.add(now, -1, :minute),
          fields: %{
            "issued_at" =>
              DateTime.to_iso8601(DateTime.add(now, -2, :day) |> DateTime.truncate(:second))
          }
        )

      assert verify(install, bytes) == {:error, :certificate_out_of_date}
    end

    test "refuses a licence issued before its certificate started", %{install: install} do
      now = DateTime.utc_now()

      bytes =
        licence(install,
          not_before: DateTime.add(now, -1, :hour),
          fields: %{
            "issued_at" =>
              DateTime.to_iso8601(DateTime.add(now, -2, :hour) |> DateTime.truncate(:second))
          }
        )

      assert verify(install, bytes) == {:error, :certificate_out_of_date}
    end
  end

  describe "this install" do
    test "a licence for another product is wrong_product", %{install: install} do
      bytes = licence(install, fields: %{"product" => "other_product"})

      assert verify(install, bytes) == {:error, :wrong_product}
      assert {:ok, _terms} = verify(install, bytes, product: "other_product")
    end

    test "refuses a licence for another machine", %{install: install, tmp_dir: dir} do
      other = install(Path.join(dir, "other"), "0000aaaa0000aaaa0000aaaa0000aaaa")

      assert verify(
               install,
               licence(install, fields: %{"machine_id_hash" => other.machine_id_hash})
             ) ==
               {:error, :wrong_machine}
    end

    test "refuses a licence naming another install key", %{install: install, tmp_dir: dir} do
      other = install(Path.join(dir, "other"))

      assert verify(install, licence(other)) == {:error, :wrong_install_key}
    end

    test "refuses an install whose key cannot sign for the public key it shows",
         %{install: install, tmp_dir: dir} do
      # A copy that kept the licence and the public key but holds another
      # private key: it answers the licence's public key, and signs with its own.
      forger = install(Path.join(dir, "forger"))

      opts =
        verify_opts(install,
          install_key:
            {Aker.TestSupport.Licences.CopiedKey,
             public_key: install.public_key, signer: forger.install_key}
        )

      assert LicenceFile.verify(licence(install), opts) == {:error, :install_key_proof_failed}
    end

    test "refuses an install with no key", %{install: install, tmp_dir: dir} do
      opts = verify_opts(install, install_key: {Software, dir: Path.join(dir, "empty")})

      assert LicenceFile.verify(licence(install), opts) == {:error, :install_key_missing}
    end
  end

  describe "the clock and the term" do
    test "refuses a clock more than a day behind the latest time seen", %{install: install} do
      now = DateTime.utc_now()
      bytes = licence(install)

      assert verify(install, bytes, last_seen: DateTime.add(now, 25, :hour)) ==
               {:error, :clock_behind}

      assert {:ok, _terms} = verify(install, bytes, last_seen: DateTime.add(now, 23, :hour))
    end

    test "refuses a term that has not started", %{install: install} do
      now = DateTime.utc_now()
      bytes = licence(install)

      assert verify(install, bytes, now: DateTime.add(now, -2, :hour)) ==
               {:error, :term_not_started}
    end

    test "refuses a term that has ended", %{install: install} do
      now = DateTime.utc_now()
      bytes = licence(install, fields: %{"term_end" => iso(DateTime.add(now, -1, :second))})

      assert verify(install, bytes) == {:error, :term_ended}
    end

    test "refuses a licence older than the one stored", %{install: install} do
      bytes = licence(install, fields: %{"serial" => 4})

      assert verify(install, bytes, stored_serial: 5) == {:error, :older_serial}
      assert {:ok, _terms} = verify(install, bytes, stored_serial: 4)
    end
  end

  test "logs each refusal by its name", %{install: install} do
    log =
      capture_log(fn ->
        assert {:error, :wrong_product} =
                 verify(install, licence(install, fields: %{"product" => "other_product"}))
      end)

    assert log =~ "licence refused: wrong_product"
  end

  describe "the root keys the app passes" do
    test "an empty root key list refuses every licence with unknown_root", %{install: install} do
      bytes = licence(install)

      assert verify(install, bytes, root_keys: []) == {:error, :unknown_root}
      assert {:ok, _terms} = verify(install, bytes)
    end

    test "a root key list that is not a list refuses with unknown_root", %{install: install} do
      assert verify(install, licence(install), root_keys: nil) == {:error, :unknown_root}
    end

    test "a certificate with Eagle's old purpose is bad_certificate", %{install: install} do
      working_key = new_key()
      now = DateTime.utc_now()

      bytes =
        Jason.encode!(%{
          "purpose" => "eagle-licence-working-key",
          "public_key" => Aker.SigningKey.public_key(working_key),
          "key_id" => "test-1",
          "not_before" => DateTime.to_iso8601(DateTime.add(now, -1, :day)),
          "not_after" => DateTime.to_iso8601(DateTime.add(now, 30, :day))
        })

      certificate = %{
        certificate: bytes,
        certificate_signature: Aker.SigningKey.sign(root_key(), bytes)
      }

      fields = licence_fields(install)

      assert verify(install, Issuer.sign(fields, working_key, certificate)) ==
               {:error, :bad_certificate}

      assert {:ok, _terms} = verify(install, licence(install, working_key: working_key))
    end
  end

  describe "features" do
    test "a licence without a features field reads features as an empty list",
         %{install: install} do
      refute Map.has_key?(licence_fields(install), "features")
      assert {:ok, %Terms{features: []}} = verify(install, licence(install))
    end

    test "a licence carries the features it was issued with", %{install: install} do
      bytes = licence(install, fields: %{"features" => ["reports", "export.csv"]})

      assert {:ok, %Terms{features: ["reports", "export.csv"]}} = verify(install, bytes)
    end

    test "the largest legitimate licence, 32 features of 32 bytes, verifies",
         %{install: install} do
      features = for n <- 1..32, do: String.pad_leading(Integer.to_string(n), 32, "f")
      customer = String.duplicate("c", 400)
      product = String.duplicate("p", 64)

      fields = %{
        "features" => features,
        "customer_name" => customer,
        "product" => product,
        "licence_id" => String.duplicate("l", 64),
        "serial" => 9_007_199_254_740_991,
        "seats" => 9_007_199_254_740_991,
        "moves_per_term" => 9_007_199_254_740_991
      }

      bytes = licence(install, key_id: String.duplicate("k", 64), fields: fields)
      licence_json = bytes |> Jason.decode!() |> Map.fetch!("licence")
      assert byte_size(licence_json) <= 5464

      assert {:ok, %Terms{features: ^features, customer_name: ^customer}} =
               verify(install, bytes, product: product)
    end

    test "33 features, or a feature of 33 bytes, is bad_licence", %{install: install} do
      many = for n <- 1..33, do: "f#{n}"
      long = [String.duplicate("f", 33)]

      for features <- [many, long, ["Reports"], [""], [1], "reports"] do
        assert verify(install, licence(install, fields: %{"features" => features})) ==
                 {:error, :bad_licence},
               inspect(features)
      end

      assert {:ok, _terms} =
               verify(install, licence(install, fields: %{"features" => Enum.take(many, 32)}))
    end
  end

  describe "limits" do
    test "a 0.3.0 licence with no limits reads %{}", %{install: install} do
      refute Map.has_key?(licence_fields(install), "limits")
      assert {:ok, %Terms{limits: limits}} = verify(install, licence(install))
      assert limits == %{}
    end

    test "reads each named limit, unlimited included", %{install: install} do
      bytes =
        licence(install,
          fields: %{
            "limits" => %{
              "clients" => 5,
              "records" => 9_007_199_254_740_991,
              "syncs" => 0,
              "assistant_tokens_per_month" => "unlimited"
            }
          }
        )

      assert {:ok, %Terms{} = terms} = verify(install, bytes)

      assert terms.limits == %{
               "clients" => 5,
               "records" => 9_007_199_254_740_991,
               "syncs" => 0,
               "assistant_tokens_per_month" => :unlimited
             }

      assert Terms.limit(terms, "clients") == 5
      assert Terms.limit(terms, "assistant_tokens_per_month") == :unlimited
    end

    test "32 limits of 32-byte names verify", %{install: install} do
      limits = Map.new(1..32, &{String.pad_leading(Integer.to_string(&1), 32, "l"), &1})

      assert {:ok, %Terms{limits: ^limits}} =
               verify(install, licence(install, fields: %{"limits" => limits}))
    end

    test "refuses malformed limits", %{install: install} do
      many = Map.new(1..33, &{"l#{&1}", 1})

      for limits <- [
            many,
            %{String.duplicate("l", 33) => 1},
            %{"Clients" => 1},
            %{"" => 1},
            %{"clients" => -1},
            %{"clients" => 1.5},
            %{"clients" => 5.0},
            %{"clients" => 9_007_199_254_740_992},
            %{"clients" => "Unlimited"},
            %{"clients" => "5"},
            %{"clients" => nil},
            %{"clients" => true},
            %{"clients" => %{"max" => 5}},
            ["clients"],
            "clients=5",
            nil
          ] do
        assert verify(install, licence(install, fields: %{"limits" => limits})) ==
                 {:error, :bad_limits},
               inspect(limits)
      end
    end

    test "logs bad_limits and never the limit's name or value", %{install: install} do
      bytes = licence(install, fields: %{"limits" => %{"secret_count" => -12_345}})
      log = capture_log(fn -> verify(install, bytes) end)
      assert log =~ "licence refused: bad_limits"
      refute log =~ "secret_count"
      refute log =~ "12345"
    end

    test "checks the signature before the limits", %{install: install} do
      envelope =
        install
        |> licence(fields: %{"limits" => %{"clients" => -1}})
        |> Jason.decode!()

      <<first, rest::binary>> = Base.decode64!(envelope["licence"])
      changed = Base.encode64(<<Bitwise.bxor(first, 1), rest::binary>>)

      assert verify(install, Jason.encode!(Map.put(envelope, "licence", changed))) ==
               {:error, :bad_signature}
    end
  end

  describe "the issuer signs only what the reader accepts" do
    setup %{install: install} do
      {:ok, request} =
        Request.build(
          product: product(),
          product_version: "2.4.1",
          install_key: install.install_key,
          machine_id_hash: install.machine_id_hash
        )

      issue = fn extra ->
        Issuer.issue(
          request,
          Keyword.merge(
            [
              product: product(),
              root_key: root_key(),
              working_key: new_key(),
              customer: "Acme",
              seats: 1,
              term_days: 30
            ],
            extra
          )
        )
      end

      %{issue: issue}
    end

    test "an option outside the reader's bounds is refused by name", %{issue: issue} do
      for {extra, option} <- [
            {[features: ["Reports"]], :features},
            {[features: for(n <- 1..33, do: "f#{n}")], :features},
            {[limits: %{"Clients" => 1}], :limits},
            {[limits: %{"clients" => -1}], :limits},
            {[limits: %{"clients" => 1.0}], :limits},
            {[limits: %{"clients" => "Unlimited"}], :limits},
            {[limits: %{"clients" => %{"max" => 1}}], :limits},
            {[limits: %{clients: 1}], :limits},
            {[limits: Map.new(1..33, &{"l#{&1}", 1})], :limits},
            {[limits: [{"clients", 1}]], :limits},
            {[customer: String.duplicate("c", 401)], :customer},
            {[customer: ""], :customer},
            {[seats: -1], :seats},
            {[serial: 0], :serial},
            {[moves_per_term: -1], :moves_per_term},
            {[key_id: String.duplicate("k", 65)], :key_id},
            {[term_days: 0], :term_days},
            {[term_days: 36_501], :term_days}
          ] do
        assert issue.(extra) == {:error, {:invalid, option}}, inspect(extra)
      end
    end

    test "a licence over the reader's 4 KB is refused", %{install: install} do
      # The longest product name, a customer of control characters (each
      # written as six bytes of JSON) and 32 features of 32 bytes.
      product = String.duplicate("p", 64)
      features = for n <- 1..32, do: String.pad_leading(Integer.to_string(n), 32, "f")

      {:ok, request} =
        Request.build(
          product: product,
          product_version: "2.4.1",
          install_key: install.install_key,
          machine_id_hash: install.machine_id_hash
        )

      opts = [
        product: product,
        root_key: root_key(),
        working_key: new_key(),
        seats: 1,
        term_days: 30,
        features: features,
        key_id: String.duplicate("k", 64)
      ]

      assert Issuer.issue(request, [customer: String.duplicate("\u0001", 400)] ++ opts) ==
               {:error, {:invalid, :size}}

      assert {:ok, _bytes} = Issuer.issue(request, [customer: String.duplicate("c", 400)] ++ opts)

      # 200 control characters fit with the features alone; the largest
      # limits, about 1.7 KB of JSON, take the same licence over.
      limits =
        Map.new(
          1..32,
          &{String.pad_leading(Integer.to_string(&1), 32, "l"), 9_007_199_254_740_991}
        )

      customer = [customer: String.duplicate("\u0001", 200)]
      assert {:ok, _bytes} = Issuer.issue(request, customer ++ opts)

      assert Issuer.issue(request, customer ++ [limits: limits] ++ opts) ==
               {:error, {:invalid, :size}}
    end

    test "signs the limits it is given, unlimited as an atom or as text",
         %{issue: issue, install: install} do
      assert {:ok, bytes} =
               issue.(limits: %{"clients" => 5, "records" => :unlimited, "syncs" => "unlimited"})

      assert {:ok, %Terms{limits: limits}} = verify(install, bytes)
      assert limits == %{"clients" => 5, "records" => :unlimited, "syncs" => :unlimited}
    end

    test "signs no limits field when it is given none", %{issue: issue, install: install} do
      for extra <- [[], [limits: %{}]] do
        assert {:ok, bytes} = issue.(extra)
        signed = bytes |> Jason.decode!() |> Map.fetch!("licence") |> Base.decode64!()
        refute signed |> Jason.decode!() |> Map.has_key?("limits")
        assert {:ok, %Terms{limits: limits}} = verify(install, bytes)
        assert limits == %{}
      end
    end

    test "the largest options it accepts make a licence the reader accepts",
         %{issue: issue, install: install} do
      features = for n <- 1..32, do: String.pad_leading(Integer.to_string(n), 32, "f")

      assert {:ok, bytes} =
               issue.(
                 customer: String.duplicate("c", 400),
                 features: features,
                 key_id: String.duplicate("k", 64),
                 term_days: 36_500
               )

      assert {:ok, %Terms{features: ^features}} = verify(install, bytes)
    end
  end

  describe "a host's own mistakes" do
    test "a missing required option raises on the first file, good or bad", %{install: install} do
      for option <- [:product, :root_keys, :machine_id_hash, :install_key] do
        opts = install |> verify_opts() |> Keyword.delete(option)
        assert_raise KeyError, fn -> LicenceFile.verify("not json", opts) end
      end
    end

    test "an install key that answers neither ok nor error is unreadable", %{install: install} do
      opts = verify_opts(install, install_key: {Aker.TestSupport.Licences.OddKey, []})

      assert LicenceFile.verify(licence(install), opts) == {:error, :install_key_unreadable}
    end

    test "a latest time seen that is not a DateTime refuses as clock_behind", %{install: install} do
      assert verify(install, licence(install), last_seen: "yesterday") == {:error, :clock_behind}
    end
  end

  defp licence_fields(install) do
    licence(install)
    |> Jason.decode!()
    |> Map.fetch!("licence")
    |> Base.decode64!()
    |> Jason.decode!()
  end

  defp iso(time), do: time |> DateTime.truncate(:second) |> DateTime.to_iso8601()
end
