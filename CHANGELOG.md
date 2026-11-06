# Changelog

All notable changes to this project will be documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and ExLicence adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Unreleased

### Added

- `ExLicence.InstallKey` makes the install key once, in the machine's TPM
  chip when it has one (`ExLicence.InstallKey.Tpm`) and in a file only the
  app's user can read otherwise (`ExLicence.InstallKey.Software`).
- `ExLicence.MachineId` hashes the host's machine id file.
- `ExLicence.Request` builds an activation request signed by the install
  key, naming the product and version the app passes, and verifies one.
- `ExLicence.SigningKey` reads an Ed25519 private key from a PEM file kept
  outside the checkout, and `ExLicence.PublicKeys` decodes a list of
  Ed25519 public keys.
