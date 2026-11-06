defmodule Aker.SignedCallTest do
  @moduledoc """
  The check a licensing server runs on a call signed by an install key:
  each refusal against a call the same check accepts.
  """
  use ExUnit.Case, async: true

  import Aker.TestSupport.Keys

  alias Aker.SignedCall

  @moduletag :tmp_dir

  @now 1_800_000_000
  @body ~s({"licence_id":"l","serial":1})

  setup %{tmp_dir: dir} do
    install = install(dir)

    {:ok, headers} =
      SignedCall.headers(install.install_key, "POST", "/api/v1/renew", @body, now: @now)

    %{install: install, headers: headers}
  end

  defp call(headers, body \\ @body),
    do: %{method: "POST", path: "/api/v1/renew", headers: headers, body: body}

  defp verify(call, extra \\ []),
    do: SignedCall.verify(call, Keyword.merge([now: @now, nonce_fresh?: fn _ -> true end], extra))

  defp put(headers, name, value), do: List.keystore(headers, name, 0, {name, value})

  test "a call signed by the install key verifies, and answers that key", ctx do
    assert verify(call(ctx.headers)) == {:ok, ctx.install.public_key}
  end

  test "a bad signature is refused", ctx do
    other = install(Path.join(ctx.tmp_dir, "other"))

    {:ok, forged} =
      SignedCall.headers(other.install_key, "POST", "/api/v1/renew", @body, now: @now)

    # The install's key, with another key's signature.
    headers =
      put(
        ctx.headers,
        "x-licence-signature",
        List.keyfind(forged, "x-licence-signature", 0) |> elem(1)
      )

    assert verify(call(headers)) == {:error, :bad_signature}
    assert verify(call(put(ctx.headers, "x-licence-signature", "!!"))) == {:error, :bad_signature}
  end

  test "a timestamp 601 s old is refused, and 599 s old is not", ctx do
    assert verify(call(ctx.headers), now: @now + 601) == {:error, :stale}
    assert verify(call(ctx.headers), now: @now - 601) == {:error, :stale}
    assert {:ok, _key} = verify(call(ctx.headers), now: @now + 599)
    assert {:ok, _key} = verify(call(ctx.headers), now: @now + 30, window_s: 60)
    assert verify(call(ctx.headers), now: @now + 61, window_s: 60) == {:error, :stale}
  end

  test "a reused nonce is refused, and a fresh one is not", ctx do
    {:ok, seen} = Agent.start_link(fn -> MapSet.new() end)

    fresh? = fn nonce ->
      Agent.get_and_update(seen, &{not MapSet.member?(&1, nonce), MapSet.put(&1, nonce)})
    end

    assert {:ok, _key} = verify(call(ctx.headers), nonce_fresh?: fresh?)
    assert verify(call(ctx.headers), nonce_fresh?: fresh?) == {:error, :replayed}

    {:ok, again} =
      SignedCall.headers(ctx.install.install_key, "POST", "/api/v1/renew", @body, now: @now)

    assert {:ok, _key} = verify(call(again), nonce_fresh?: fresh?)
  end

  test "a forged call records no nonce", ctx do
    test = self()
    fresh? = fn nonce -> send(test, {:nonce, nonce}) == {:nonce, nonce} end

    assert verify(call(ctx.headers, "{}"), nonce_fresh?: fresh?) == {:error, :bad_signature}
    refute_received {:nonce, _nonce}
  end

  test "a changed body, method or path is refused", ctx do
    assert verify(call(ctx.headers, ~s({"licence_id":"l","serial":2}))) ==
             {:error, :bad_signature}

    assert verify(%{call(ctx.headers) | method: "PUT"}) == {:error, :bad_signature}
    assert verify(%{call(ctx.headers) | path: "/api/v1/refresh"}) == {:error, :bad_signature}
  end

  test "a key off the curve is refused", ctx do
    off_curve = put(ctx.headers, "x-licence-install-key", Base.encode64(<<4, 0::512>>))

    assert verify(call(off_curve)) == {:error, :bad_key}
    assert verify(call(put(ctx.headers, "x-licence-install-key", "AAAA"))) == {:error, :bad_key}
  end

  test "a nonce that is not 16 bytes is refused", ctx do
    nonce = Base.encode64(:crypto.strong_rand_bytes(15))
    assert verify(call(put(ctx.headers, "x-licence-nonce", nonce))) == {:error, :bad_nonce}
  end

  test "a missing or repeated header is unsigned", ctx do
    for name <- ~w(x-licence-install-key x-licence-timestamp x-licence-nonce x-licence-signature) do
      assert verify(call(List.keydelete(ctx.headers, name, 0))) == {:error, :unsigned}, name
      doubled = ctx.headers ++ [List.keyfind(ctx.headers, name, 0)]
      assert verify(call(doubled)) == {:error, :unsigned}, name
    end

    assert verify(%{method: "POST"}) == {:error, :unsigned}
  end
end
