//! Constant functions for converting hex- and base64-encoded strings into bytes.
//! Works on stable Rust and in no-std environments. Base-(2,4,8,16,32,64) encodings with
//! custom alphabets are supported as well via [`Encoding`].
//!
//! [`Decoder`] is the base type encapsulating decoding logic, with [`SkipWhitespace`]
//! and [`Pem`] types providing its variations with slightly different properties.
//! (For example, `Pem` allows to parse PEM files.)
//!
//! Methods in base types require specifying the length of the output byte array, either in its type,
//! or using the turbofish syntax (see the examples below). To avoid this, you can instead use
//! the [`decode!`] macro.
//!
//! Conversions are primarily useful for testing, but can be used in other contexts as well.
//!
//! # Alternatives
//!
//! [`hex-literal`] and [`binary_macros`] crates expose similar functionality
//! as procedural macros. Because of this, macros cannot be used in no-std environments,
//! while this approach can.
//!
//! In the longer-term (after stabilizing [const mutable refs], etc.)
//! it should become possible to use "ordinary" encoding crates, such as [`hex`].
//!
//! [const mutable refs]: https://github.com/rust-lang/rust/issues/57349
//! [`binary_macros`]: https://crates.io/crates/binary_macros
//! [`hex-literal`]: https://crates.io/crates/hex_literal
//! [`hex`]: https://crates.io/crates/hex
//!
//! # Examples
//!
//! ```
//! use const_decoder::Decoder;
//! // An Ed25519 secret key.
//! const SECRET_KEY: [u8; 64] = Decoder::Hex.decode(
//!     b"9e55d1e1aa1f455b8baad9fdf975503655f8b359d542fa7e4ce84106d625b352\
//!       06fac1f22240cffd637ead6647188429fafda9c9cb7eae43386ac17f61115075",
//! );
//! ```
//!
//! Same input string decoded using [`decode!`]:
//!
//! ```
//! use const_decoder::{decode, Decoder};
//!
//! const SECRET_KEY: &[u8] = &decode!(
//!     Decoder::Hex,
//!     b"9e55d1e1aa1f455b8baad9fdf975503655f8b359d542fa7e4ce84106d625b352\
//!       06fac1f22240cffd637ead6647188429fafda9c9cb7eae43386ac17f61115075",
//! );
//! ```
//!
//! Note how specifying the output length is avoided by placing the `decode!` output behind a reference.
//!
//! [`include_bytes!`] macro works as well.
//!
//! ```
//! # use const_decoder::{decode, Pem};
//! # // We don't actually want to access FS in tests, so we hack the `include_bytes` macro.
//! # macro_rules! include_bytes {
//! #     ($path:tt) => { &[b'A'; 1184] };
//! # }
//! const CERT: &[u8] = &decode!(Pem, include_bytes!("certificate.crt"));
//! ```
//!
//! Naturally, all code works in the runtime context as well.
//!
//! ```
//! # use const_decoder::Decoder;
//! let public_key: [u8; 32] = Decoder::Hex.decode(
//!     b"06fac1f22240cffd637ead6647188429fafda9c9cb7eae43386ac17f61115075",
//! );
//! let other_public_key: [u8; 32] = Decoder::Base64.decode(
//!     b"6IcUt5J4tArK8SR8SpBZb8Rp7E7kyvaTfv9N8WlOinw=",
//! );
//! ```
//!
//! ## Compile-time errors
//!
//! The code will fail to compile if there is an error in the literal:
//!
//! ```compile_fail
//! # use const_decoder::Decoder;
//! // The provided hex string is too short
//! const BOGUS: [u8; 32] = Decoder::Hex.decode(b"c0ffee");
//! ```
//!
//! ```compile_fail
//! # use const_decoder::Decoder;
//! // The provided hex string is too long
//! const BOGUS: [u8; 3] = Decoder::Hex.decode(b"c01dbeef");
//! ```
//!
//! ```compile_fail
//! # use const_decoder::Decoder;
//! // The provided string contains invalid chars
//! const BOGUS: [u8; 5] = Decoder::Hex.decode(b"c0ffeecup");
//! ```

#![no_std]
// Documentation settings.
#![doc(html_root_url = "https://docs.rs/const-decoder/0.4.0")]
// Linter settings.
#![warn(missing_debug_implementations, missing_docs, bare_trait_objects)]
#![warn(clippy::all, clippy::pedantic)]
#![allow(clippy::must_use_candidate, clippy::shadow_unrelated)]

pub use crate::{
    decoder::{Decoder, Encoding},
    macros::DecoderWrapper,
    wrappers::{Pem, SkipWhitespace},
};

mod decoder;
mod macros;
#[cfg(test)]
mod tests;
mod wrappers;

#[cfg(doctest)]
doc_comment::doctest!("../README.md");
