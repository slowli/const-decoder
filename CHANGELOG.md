# Changelog

All notable changes to this project will be documented in this file.
The project adheres to [Semantic Versioning](http://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Add `decode!` macro that allows to skip specifying output length.
- Make panic messages more informative by including context information.

### Changed

- Bump MSRV to 1.67.

## 0.3.0 - 2022-11-01

### Added

- Add `Decoder::custom()` as a shortcut for `Decoder::Custom(Encoding::new(alphabet))`.

### Changed

- Bump MSRV to 1.57, switch to 2021 edition and remove the `nightly` feature as obsolete.

## 0.2.0 - 2021-10-10

### Added

- Support URL-safe variant of base64 encoding.
- Support base-(2,4,8,16,32,64) encodings with custom alphabets.
- Add `nightly` feature (requires a nightly Rust toolchain) for improved panic 
  messages.

### Changed

- Rename `SkipWhitespace::parse()` and `Pem::parse()` methods to `decode()`
  for uniformity with `Decoder::decode`.
- Mark `Decoder` enum as non-exhaustive.

### Fixed

- Check final decoder state, preventing error such as an odd number of hex digits
  or invalid terminal base64 char.

## 0.1.0 - 2021-04-16

The initial release of `const-decoder`.
