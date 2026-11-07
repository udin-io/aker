# Changelog

All notable changes to this project will be documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and Aker adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## v0.3.0 — 2026-11-07

An app can tell the licensing server what it runs at each check-in.

### Added

- `Aker.Gate` takes `:check_in_fields`, a function that returns extra
  fields for each renewal and refresh body. The install key signs them with
  the rest of the body. They never replace `licence_id` or `serial`. The
  function runs in its own process for at most `:check_in_fields_timeout`
  (default 5 s). One that fails, runs longer, or returns non-string keys at
  any depth, a value JSON cannot hold or more than 8 KB of JSON sends the
  call without them.
- `Aker.Client.renew/4` and `refresh/4` take those fields.

### Unchanged

- An app that leaves the option out sends the same body as before.
- Activation sends no extra fields.

## v0.2.0 — 2026-11-07

A licensing server can sign licences without holding the root key.

### Added

- `mix aker.certify` signs a working key's certificate with the root key,
  offline, and prints it on one line. It never prints the working key.
- `Aker.Issuer.issue/2` takes `:certificate` and `:root_keys` in place of
  `:root_key`. It refuses a certificate no listed root signed, one for
  another working key, one not in date, and a term that ends after the
  certificate does.
- `Aker.Issuer.issue/2` takes `:licence_id`, so a renewal keeps its id,
  and `:term_start` with `:term_end` in place of `:term_days`.
- `Aker.Issuer.encode_certificate/1` and `decode_certificate/1` keep a
  certificate as one line of at most 2 KB.
- `Aker.LicenceFile.read_certificate/3` reads a certificate a root key
  signed, with the checks `verify/2` runs.
- `Aker.Request.verify/2` also answers the product version, the install
  key's kind, the time and the nonce, and refuses a request whose key kind
  is neither `software` nor `tpm`.

### Unchanged

- `mix aker.sign` signs as before, with the root key.

## v0.1.0 — 2026-11-06

The first release.

### Added

- `Aker.InstallKey` makes the install key once, in the machine's TPM
  chip when it has one (`Aker.InstallKey.Tpm`) and in a file only the
  app's user can read otherwise (`Aker.InstallKey.Software`).
- `Aker.MachineId` hashes the host's machine id file.
- `Aker.Request` builds an activation request signed by the install
  key, naming the product and version the app passes, and verifies one.
- `Aker.SigningKey` reads an Ed25519 private key from a PEM file kept
  outside the checkout, and `Aker.PublicKeys` decodes a list of
  Ed25519 public keys.
- `Aker.LicenceFile` checks a signed licence file against the root
  public keys the app passes, in a fixed order with one refusal reason per
  check. An empty root key list accepts no licence. A licence may list up
  to 32 features beside its seats.
- `Aker.Issuer` signs a licence from an activation request, and
  `mix aker.sign` runs it from the command line with keys kept
  outside the checkout.
- `Aker.Gate` checks the licence at boot and every hour, holds the lock
  state where every reader finds it, renews the licence in its term's last
  week, and calls the app back when the install locks or unlocks. A gate
  that never ran reads locked.
- `Aker.Store` is the contract for where an app keeps its licence.
- `Aker.Client` makes the calls to the licensing server, and
  `Aker.SignedCall` signs them with the install key and checks them on the
  server's side.
