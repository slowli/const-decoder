# Changelog

All notable changes to this project will be documented in this file.
The project adheres to [Semantic Versioning](http://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Support URL-safe variant of base64 encoding.

### Changed

- Rename `SkipWhitespace::parse()` and `Pem::parse()` methods to `decode()`
  for uniformity with `Decoder::decode`.

## 0.1.0 - 2021-04-16

The initial release of `const-decoder`.
