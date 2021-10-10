# Changelog

All notable changes to this project will be documented in this file.
The project adheres to [Semantic Versioning](http://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Support URL-safe variant of base64 encoding.
- Support base-(2,4,8,16,32,64) encodings with custom alphabets.
- Add `nightly` feature (requires a nightly Rust toolchain) for improved panic 
  messages.

### Changed

- Rename `SkipWhitespace::parse()` and `Pem::parse()` methods to `decode()`
  for uniformity with `Decoder::decode`.

### Fixed

- Check final decoder state, preventing error such as an odd number of hex digits
  or invalid terminal base64 char.

## 0.1.0 - 2021-04-16

The initial release of `const-decoder`.
