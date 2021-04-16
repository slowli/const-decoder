//! Converting hex- and base64-encoded strings into bytes as constant functions.
//! Works on stable Rust and in no-std environments.
//!
//! [`Decoder`] is the base type encapsulating decoding logic, with [`SkipWhitespace`]
//! and [`Pem`] types providing its variations with slightly different properties.
//! (For example, `Pem` allows to parse PEM files.)
//!
//! Conversions are primarily useful for testing, but can be used in other contexts as well.
//!
//! # Limitations
//!
//! - Compile-time assertions rely on a hack since [const panics] are not stable yet
//!   as of Rust 1.51. This produces *sort of* reasonable error messages in compile time,
//!   but in runtime the error messages could be better.
//! - Length of the output byte array needs to be specified, either in its type, or using
//!   turbofish syntax (see the examples below). This could be a positive in some cases;
//!   e.g., keys in cryptography frequently have an expected length, and specifying it can prevent
//!   key mix-up.
//!
//! # Alternatives
//!
//! [`hex-literal`] and [`binary_macros`] crates expose similar functionality
//! as procedural macros. Because of this, macros cannot be used in no-std environments,
//! while this approach can.
//!
//! In the longer-term (after stabilizing [const panics], [const mutable refs], etc.)
//! it should become possible to use "ordinary" encoding crates, such as [`hex`].
//!
//! [const panics]: https://github.com/rust-lang/rust/issues/51999
//! [const mutable refs]: https://github.com/rust-lang/rust/issues/57349
//! [type params for const fns]: https://github.com/rust-lang/rfcs/pull/2632
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
//! [`include_bytes!`] macro works as well, although it is necessary to specify bytes length.
//!
//! ```
//! # use const_decoder::Pem;
//! # // We don't actually want to access FS in tests, so we hack the `include_bytes` macro.
//! # macro_rules! include_bytes {
//! #     ($path:tt) => { &[b'A'; 1184] };
//! # }
//! const CERT: &[u8] = &Pem::parse::<888>(include_bytes!("certificate.crt"));
//! ```
//!
//! Naturally, all code works in the runtime context as well, although panic messages
//! may be not quite comprehensible.
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
#![doc(html_root_url = "https://docs.rs/const-decoder/0.1.0")]
// Linter settings.
#![warn(missing_debug_implementations, missing_docs, bare_trait_objects)]
#![warn(clippy::all, clippy::pedantic)]
#![allow(clippy::must_use_candidate, clippy::shadow_unrelated)]

// TODO: replace with `assert` once https://github.com/rust-lang/rust/issues/51999 is stabilized.
macro_rules! const_assert {
    ($condition:expr, $msg:tt) => {
        [$msg][!($condition) as usize];
    };
}

/// Internal state of the hexadecimal decoder.
#[derive(Debug, Clone, Copy)]
struct HexDecoderState(Option<u8>);

impl HexDecoderState {
    #[allow(unconditional_panic)]
    // ^-- Required since ordinary `panic`s are not yet stable in const context
    const fn byte_value(val: u8) -> u8 {
        match val {
            b'0'..=b'9' => val - b'0',
            b'A'..=b'F' => val - b'A' + 10,
            b'a'..=b'f' => val - b'a' + 10,
            _ => {
                const_assert!(false, "Invalid character in input; expected a hex digit");
                0
            }
        }
    }

    const fn new() -> Self {
        Self(None)
    }

    #[allow(clippy::option_if_let_else)] // `Option::map_or_else` cannot be used in const fns
    const fn update(mut self, byte: u8) -> (Self, Option<u8>) {
        let byte = Self::byte_value(byte);
        let output = if let Some(b) = self.0 {
            self.0 = None;
            Some((b << 4) + byte)
        } else {
            self.0 = Some(byte);
            None
        };
        (self, output)
    }
}

/// Internal state of a Base64 decoder.
#[derive(Debug, Clone, Copy)]
struct Base64DecoderState {
    partial_byte: u8,
    filled_bits: u8,
}

impl Base64DecoderState {
    #[allow(unconditional_panic)]
    // ^-- Required since ordinary `panic`s are not yet stable in const context
    const fn byte_value(val: u8) -> u8 {
        match val {
            b'A'..=b'Z' => val - b'A',
            b'a'..=b'z' => val - b'a' + 26,
            b'0'..=b'9' => val - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => {
                const_assert!(false, "Invalid character in input; expected a Base64 digit");
                0 // unreachable
            }
        }
    }

    const fn new() -> Self {
        Self {
            partial_byte: 0,
            filled_bits: 0,
        }
    }

    const fn update(mut self, byte: u8) -> (Self, Option<u8>) {
        if byte == b'=' {
            return (self, None);
        }

        let byte = Self::byte_value(byte);
        let output = match self.filled_bits {
            0 | 1 => {
                self.partial_byte = (self.partial_byte << 6) + byte;
                self.filled_bits += 6;
                None
            }
            2 => {
                let output = (self.partial_byte << 6) + byte;
                self.partial_byte = 0;
                self.filled_bits = 0;
                Some(output)
            }
            3..=7 => {
                let remaining_bits = 8 - self.filled_bits; // in 1..=5
                let new_filled_bits = 6 - remaining_bits;
                let output = (self.partial_byte << remaining_bits) + (byte >> new_filled_bits);
                self.partial_byte = byte % (1 << new_filled_bits);
                self.filled_bits = new_filled_bits;
                Some(output)
            }

            // This is unreachable, but `unreachable` / `unreachable_unchecked` are
            // not stable in the const context.
            _ => None,
        };
        (self, output)
    }
}

/// State of a decoder.
#[derive(Debug, Clone, Copy)]
enum DecoderState {
    Hex(HexDecoderState),
    Base64(Base64DecoderState),
}

impl DecoderState {
    const fn update(self, byte: u8) -> (Self, Option<u8>) {
        match self {
            Self::Hex(state) => {
                let (updated_state, output) = state.update(byte);
                (Self::Hex(updated_state), output)
            }
            Self::Base64(state) => {
                let (updated_state, output) = state.update(byte);
                (Self::Base64(updated_state), output)
            }
        }
    }
}

/// Decoder of a human-friendly encoding, such as hex or base64, into bytes.
///
/// # Examples
///
/// See the [crate docs](index.html) for examples of usage.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Decoder {
    /// Hexadecimal decoder. Supports uppercase and lowercase digits.
    Hex,
    /// Base64 decoder. Does not require padding, but works fine with it.
    Base64,
}

impl Decoder {
    /// Marks that this coder
    pub const fn skip_whitespace(self) -> SkipWhitespace {
        SkipWhitespace(self)
    }

    const fn new_state(self) -> DecoderState {
        match self {
            Self::Hex => DecoderState::Hex(HexDecoderState::new()),
            Self::Base64 => DecoderState::Base64(Base64DecoderState::new()),
        }
    }

    /// Decodes `input` into a byte array.
    ///
    /// # Panics
    ///
    /// - Panics if the provided length is insufficient or too large for `input`.
    /// - Panics if `input` contains invalid chars.
    pub const fn decode<const N: usize>(self, input: &[u8]) -> [u8; N] {
        self.do_decode(input, None)
    }

    const fn do_decode<const N: usize>(self, input: &[u8], skipper: Option<Skipper>) -> [u8; N] {
        let mut bytes = [0_u8; N];
        let mut in_index = 0;
        let mut out_index = 0;
        let mut state = self.new_state();

        while in_index < input.len() {
            if let Some(skipper) = skipper {
                let new_in_index = skipper.skip(input, in_index);
                if new_in_index != in_index {
                    in_index = new_in_index;
                    continue;
                }
            }

            let update = state.update(input[in_index]);
            state = update.0;
            if let Some(byte) = update.1 {
                bytes[out_index] = byte;
                out_index += 1;
            }
            in_index += 1;
        }
        const_assert!(out_index == N, "Not all bytes of output were written");
        bytes
    }
}

/// [`Decoder`] wrapper that skips whitespace during decoding instead of panicking.
///
/// # Examples
///
/// ```
/// # use const_decoder::{Decoder, SkipWhitespace};
/// const KEY: [u8; 64] = SkipWhitespace(Decoder::Hex).parse(b"
///     9e55d1e1 aa1f455b 8baad9fd f9755036 55f8b359 d542fa7e
///     4ce84106 d625b352 06fac1f2 2240cffd 637ead66 47188429
///     fafda9c9 cb7eae43 386ac17f 61115075
/// ");
/// # assert_eq!(KEY[0], 0x9e);
/// # assert_eq!(KEY[63], 0x75);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SkipWhitespace(pub Decoder);

impl SkipWhitespace {
    /// Decodes `input` into a byte array.
    ///
    /// # Panics
    ///
    /// - Panics if the provided length is insufficient or too large for `input`.
    /// - Panics if `input` contains invalid chars.
    pub const fn parse<const N: usize>(self, input: &[u8]) -> [u8; N] {
        self.0.do_decode(input, Some(Skipper::Whitespace))
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum Skipper {
    Whitespace,
    Pem,
}

impl Skipper {
    const fn detect_pem_header(input: &[u8], mut i: usize) -> Option<usize> {
        if input.len() < i + 5 {
            None
        } else if input[i] == b'-'
            && input[i + 1] == b'-'
            && input[i + 2] == b'-'
            && input[i + 3] == b'-'
            && input[i + 4] == b'-'
        {
            i += 5;
            while i < input.len() && input[i] != b'\n' {
                i += 1;
            }
            Some(i)
        } else {
            None
        }
    }

    const fn skip(self, input: &[u8], mut in_index: usize) -> usize {
        if input[in_index].is_ascii_whitespace() {
            in_index += 1;
        } else if let Self::Pem = self {
            if let Some(new_in_index) = Self::detect_pem_header(input, in_index) {
                in_index = new_in_index;
            }
        }
        in_index
    }
}

/// Decoder for the PEM file format (Base64 with additional header / trailer lines).
///
/// # Examples
///
/// ```
/// # use const_decoder::Pem;
/// // X.25519 private key generated using OpenSSL:
/// // `openssl genpkey -algorithm X25519`.
/// const PRIVATE_KEY: [u8; 48] = Pem::parse(
///     b"-----BEGIN PRIVATE KEY-----
///       MC4CAQAwBQYDK2VuBCIEINAOV4yAyaoM2wmJPApQs3byDhw7oJRG47V0VHwGnctD
///       -----END PRIVATE KEY-----",
/// );
/// ```
#[derive(Debug, Clone, Copy)]
pub struct Pem;

impl Pem {
    /// Decodes `input` into a byte array.
    ///
    /// # Panics
    ///
    /// - Panics if the provided length is insufficient or too large for `input`.
    /// - Panics if `input` contains invalid chars.
    pub const fn parse<const N: usize>(input: &[u8]) -> [u8; N] {
        Decoder::Base64.do_decode(input, Some(Skipper::Pem))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_codec() {
        const KEY: [u8; 4] = Decoder::Hex.decode(b"1234567f");
        assert_eq!(KEY, [0x12, 0x34, 0x56, 0x7f]);
    }

    #[test]
    fn hex_codec_with_whitespace() {
        const KEY: [u8; 4] = Decoder::Hex.skip_whitespace().parse(b"12\n34  56\t7f");
        assert_eq!(KEY, [0x12, 0x34, 0x56, 0x7f]);
    }

    #[test]
    fn base64_codec_in_compile_time() {
        const SAMPLES: &[(&[u8], &[u8])] = &[
            (&Decoder::Base64.decode::<4>(b"dGVzdA=="), b"test"),
            (
                &Decoder::Base64.decode::<11>(b"VGVzdCBzdHJpbmc="),
                b"Test string",
            ),
            (
                &Decoder::Base64.decode::<18>(b"TG9uZ2VyIHRlc3Qgc3RyaW5n"),
                b"Longer test string",
            ),
        ];
        for &(actual, expected) in SAMPLES {
            assert_eq!(actual, expected);
        }
    }

    #[test]
    fn base64_with_small_bytes() {
        assert_eq!(Decoder::Base64.decode::<3>(b"MIID"), [48, 130, 3]);
    }

    #[test]
    fn base64_codec_in_runtime() {
        let s: [u8; 4] = Decoder::Base64.decode(b"dGVzdA==");
        assert_eq!(s, *b"test");
        let s: [u8; 4] = Decoder::Base64.decode(b"dGVzdA");
        assert_eq!(s, *b"test");
        let s: [u8; 6] = Decoder::Base64.decode(b"Pj4+Pz8/");
        assert_eq!(s, *b">>>???");
        let s: [u8; 11] = Decoder::Base64.decode(b"VGVzdCBzdHJpbmc=");
        assert_eq!(s, *b"Test string");
        let s: [u8; 18] = Decoder::Base64.decode(b"TG9uZ2VyIHRlc3Qgc3RyaW5n");
        assert_eq!(s, *b"Longer test string");
    }
}
