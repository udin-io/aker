# Changelog

All notable changes to this project will be documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and Aker adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
