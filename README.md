# Constant Functions for Hex / Base64 Decoding

[![Build Status](https://github.com/slowli/const-decoder/workflows/CI/badge.svg?branch=master)](https://github.com/slowli/const-decoder/actions)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/License-MIT%2FApache--2.0-blue)](https://github.com/slowli/const-decoder#license)
![rust 1.67+ required](https://img.shields.io/badge/rust-1.67+-blue.svg?label=Required%20Rust)

**Documentation:** [![Docs.rs](https://img.shields.io/docsrs/const-decoder)](https://docs.rs/const-decoder/)
[![crate docs (master)](https://img.shields.io/badge/master-yellow.svg?label=docs)](https://slowli.github.io/const-decoder/const_decoder/)

Constant functions for converting hex- and base64-encoded strings into bytes in Rust.
Works on stable Rust and in no-std environments. Base-(2,4,8,16,32,64) encodings with
custom alphabets are supported as well.

## Usage

Add this to your `Crate.toml`:

```toml
[dependencies]
const-decoder = "0.3.0"
```

Example of usage:

```rust
use const_decoder::Decoder;
// An Ed25519 secret key.
const SECRET_KEY: [u8; 64] = Decoder::Hex.decode(
    b"9e55d1e1aa1f455b8baad9fdf975503655f8b359d542fa7e4ce84106d625b352\
      06fac1f22240cffd637ead6647188429fafda9c9cb7eae43386ac17f61115075",
);
// Alternatively, you can use `decode!` macro:
const PUBLIC_KEY: &[u8] = &const_decoder::decode!(
    Decoder::Hex,
    b"06fac1f22240cffd637ead6647188429fafda9c9cb7eae43386ac17f61115075",
);
```

[Bech32] encoding:

```rust
use const_decoder::{Decoder, Encoding};
const BECH32: Decoder = Decoder::custom("qpzry9x8gf2tvdw0s3jn54khce6mua7l");
// Sample address from the Bech32 spec excluding the `tb1q` prefix
// and the checksum suffix.
const SAMPLE_ADDR: [u8; 32] =
    BECH32.decode(b"rp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q");
```

See more examples in the crate docs.

## Alternatives

[`hex-literal`] and [`binary_macros`] crates expose similar functionality
as procedural macros. Because of this, macros cannot be used in no-std environments,
while this approach can.

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE)
or [MIT license](LICENSE-MIT) at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in `const-decoder` by you, as defined in the Apache-2.0 license,
shall be dual licensed as above, without any additional terms or conditions.

[Bech32]: https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki
[`binary_macros`]: https://crates.io/crates/binary_macros
[`hex-literal`]: https://crates.io/crates/hex_literal
