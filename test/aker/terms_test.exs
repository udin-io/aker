defmodule Aker.TermsTest do
  use ExUnit.Case, async: true

  import Aker.TestSupport.Keys
  import Aker.TestSupport.Licences

  alias Aker.LicenceFile
  alias Aker.Terms

  @moduletag :tmp_dir
  @moduletag :capture_log

  setup %{tmp_dir: dir} do
    install = install(dir)
    bytes = licence(install, fields: %{"limits" => %{"clients" => 5, "messages" => "unlimited"}})
    {:ok, terms} = LicenceFile.verify(bytes, verify_opts(install))
    %{terms: terms}
  end

  test "a limit reads the number or unlimited the licence carries", %{terms: terms} do
    assert Terms.limit(terms, "clients") == 5
    assert Terms.limit(terms, "messages") == :unlimited
  end

  test "a limit the licence leaves out reads 0", %{terms: terms} do
    assert Terms.limit(terms, "records") == 0
  end
end
