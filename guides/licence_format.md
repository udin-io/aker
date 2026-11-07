# Licence format

Everything here is JSON. Binary values are base64 with padding. Times are
UTC, ISO 8601, to the second.

## The activation request

The install sends an object with two fields:

- `request`: the request JSON bytes;
- `signature`: the install key's DER ECDSA P-256 SHA-256 signature of them.

The request JSON holds `product`, `product_version`, `install_public_key`
(the 65-byte uncompressed P-256 point), `install_key_kind` (`software` or
`tpm`), `machine_id_hash` (SHA-256 of the trimmed machine id, lowercase hex),
`created_at` and `nonce` (16 random bytes). A reader takes at most 8 KB.

## The licence file

An object with four fields:

- `licence`: the licence JSON bytes;
- `signature`: the working key's Ed25519 signature of them;
- `certificate`: the working key's certificate JSON bytes;
- `certificate_signature`: a root key's Ed25519 signature of the certificate.

The certificate holds `purpose` (`licence-working-key`), `public_key` (the
working key, 32 bytes), `key_id`, `not_before` and `not_after`.

### Certifying a working key

A licensing server signs with a working key, never the root key. You certify
each working key offline, on the machine that holds the root key:

```sh
mix aker.certify --root-key ../keys/root.pem \
  --working-key ../keys/working-2026-11.pem --key-id w-2026-11 --days 470
```

It prints the certificate as one line, `{"certificate": "<base64>",
"certificate_signature": "<base64>"}`, at most 2 KB. The server keeps that line
and the working key, and passes both to `Aker.Issuer.issue/2` as
`:certificate` (through `Aker.Issuer.decode_certificate/1`) and
`:working_key`, with the root public keys as `:root_keys`. The issuer refuses a
term that ends after the certificate's `not_after`, since an install refuses
the licence once the certificate lapses.

The licence holds `licence_id`, `serial`, `product`, `customer_name`,
`install_public_key`, `machine_id_hash`, `term_start`, `term_end`, `seats`,
`moves_per_term`, `issued_at`, `working_key_id`, and optionally `features`: up
to 32 names of 1 to 32 bytes of `a-z 0-9 _ . -`.

A reader takes at most 64 KB, checks each signature over the exact bytes it
received, and reads no field before the signature holds.

## A signed call

`renew` and `refresh` send `{"licence_id", "serial"}` and any fields the
app's `check_in_fields` adds, and carry four headers:

- `x-licence-install-key`: the install public key;
- `x-licence-timestamp`: Unix seconds;
- `x-licence-nonce`: 16 random bytes;
- `x-licence-signature`: the install key's signature of the method, the path,
  the timestamp, the nonce and the body's SHA-256 in hex, one per line.

The server refuses a timestamp more than 10 minutes off and a nonce it has
seen. `Aker.SignedCall.verify/2` runs these checks.

## The server's answers

- `200` with `{"licence_file": "<the licence file>"}`;
- any other status with `{"error": "<code>"}`. The client keeps the code as
  text of at most 64 characters.
