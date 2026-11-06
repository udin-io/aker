# Changelog

All notable changes to this project will be documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and Aker adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Unreleased

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
