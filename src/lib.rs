//! Constant functions for converting hex- and base64-encoded strings into bytes.
//! Works on stable Rust and in no-std environments. Base-(2,4,8,16,32,64) encodings with
//! custom alphabets are supported as well via [`Encoding`].
//!
//! [`Decoder`] is the base type encapsulating decoding logic, with [`SkipWhitespace`]
//! and [`Pem`] types providing its variations with slightly different properties.
//! (For example, `Pem` allows to parse PEM files.)
//!
//! Conversions are primarily useful for testing, but can be used in other contexts as well.
//!
//! # Limitations
//!
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
//! const CERT: &[u8] = &Pem::decode::<888>(include_bytes!("certificate.crt"));
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
#![doc(html_root_url = "https://docs.rs/const-decoder/0.2.0")]
// Linter settings.
#![warn(missing_debug_implementations, missing_docs, bare_trait_objects)]
#![warn(clippy::all, clippy::pedantic)]
#![allow(clippy::must_use_candidate, clippy::shadow_unrelated)]

/// Internal state of the hexadecimal decoder.
#[derive(Debug, Clone, Copy)]
struct HexDecoderState(Option<u8>);

impl HexDecoderState {
    const fn byte_value(val: u8) -> u8 {
        match val {
            b'0'..=b'9' => val - b'0',
            b'A'..=b'F' => val - b'A' + 10,
            b'a'..=b'f' => val - b'a' + 10,
            _ => panic!("Invalid character in input; expected a hex digit"),
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

    const fn is_final(self) -> bool {
        self.0.is_none()
    }
}

/// Internal state of a Base64 decoder.
#[derive(Debug, Clone, Copy)]
struct CustomDecoderState {
    table: Encoding,
    partial_byte: u8,
    filled_bits: u8,
}

impl CustomDecoderState {
    const fn new(table: Encoding) -> Self {
        Self {
            table,
            partial_byte: 0,
            filled_bits: 0,
        }
    }

    #[allow(clippy::comparison_chain)] // not feasible in const context
    const fn update(mut self, byte: u8) -> (Self, Option<u8>) {
        let byte = self.table.lookup(byte);
        let output = if self.filled_bits < 8 - self.table.bits_per_char {
            self.partial_byte = (self.partial_byte << self.table.bits_per_char) + byte;
            self.filled_bits += self.table.bits_per_char;
            None
        } else if self.filled_bits == 8 - self.table.bits_per_char {
            let output = (self.partial_byte << self.table.bits_per_char) + byte;
            self.partial_byte = 0;
            self.filled_bits = 0;
            Some(output)
        } else {
            let remaining_bits = 8 - self.filled_bits;
            let new_filled_bits = self.table.bits_per_char - remaining_bits;
            let output = (self.partial_byte << remaining_bits) + (byte >> new_filled_bits);
            self.partial_byte = byte % (1 << new_filled_bits);
            self.filled_bits = new_filled_bits;
            Some(output)
        };
        (self, output)
    }

    const fn is_final(&self) -> bool {
        // We don't check `self.filled_bits` because padding may be implicit
        self.partial_byte == 0
    }
}

/// State of a decoder.
#[derive(Debug, Clone, Copy)]
enum DecoderState {
    Hex(HexDecoderState),
    Base64(CustomDecoderState),
    Custom(CustomDecoderState),
}

impl DecoderState {
    const fn update(self, byte: u8) -> (Self, Option<u8>) {
        match self {
            Self::Hex(state) => {
                let (updated_state, output) = state.update(byte);
                (Self::Hex(updated_state), output)
            }
            Self::Base64(state) => {
                if byte == b'=' {
                    (self, None)
                } else {
                    let (updated_state, output) = state.update(byte);
                    (Self::Base64(updated_state), output)
                }
            }
            Self::Custom(state) => {
                let (updated_state, output) = state.update(byte);
                (Self::Custom(updated_state), output)
            }
        }
    }

    const fn is_final(&self) -> bool {
        match self {
            Self::Hex(state) => state.is_final(),
            Self::Base64(state) | Self::Custom(state) => state.is_final(),
        }
    }
}

/// Decoder of a human-friendly encoding, such as hex or base64, into bytes.
///
/// # Examples
///
/// See the [crate docs](index.html) for examples of usage.
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub enum Decoder {
    /// Hexadecimal decoder. Supports uppercase and lowercase digits.
    Hex,
    /// Base64 decoder accepting standard encoding as per [RFC 3548].
    /// Does not require padding, but works fine with it.
    ///
    /// [RFC 3548]: https://datatracker.ietf.org/doc/html/rfc3548.html
    Base64,
    /// Base64 decoder accepting URL / filesystem-safe encoding as per [RFC 3548].
    /// Does not require padding, but works fine with it.
    ///
    /// [RFC 3548]: https://datatracker.ietf.org/doc/html/rfc3548.html
    Base64Url,
    /// Decoder based on a custom [`Encoding`].
    Custom(Encoding),
}

impl Decoder {
    /// Makes this decoder skip whitespace chars rather than panicking on encountering them.
    pub const fn skip_whitespace(self) -> SkipWhitespace {
        SkipWhitespace(self)
    }

    const fn new_state(self) -> DecoderState {
        match self {
            Self::Hex => DecoderState::Hex(HexDecoderState::new()),
            Self::Base64 => DecoderState::Base64(CustomDecoderState::new(Encoding::BASE64)),
            Self::Base64Url => DecoderState::Base64(CustomDecoderState::new(Encoding::BASE64_URL)),
            Self::Custom(encoding) => DecoderState::Custom(CustomDecoderState::new(encoding)),
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
                assert!(
                    out_index < N,
                    "Output overflow: the input decodes to more bytes than specified \
                     as the output length"
                );
                bytes[out_index] = byte;
                out_index += 1;
            }
            in_index += 1;
        }
        assert!(
            out_index == N,
            "Output underflow: the input was decoded into less bytes than specified \
             as the output length"
        );
        assert!(
            state.is_final(),
            "Left-over state after processing input. This usually means that the input \
             is incorrect (e.g., an odd number of hex digits)."
        );
        bytes
    }
}

/// [`Decoder`] wrapper that skips whitespace during decoding instead of panicking.
///
/// # Examples
///
/// ```
/// # use const_decoder::{Decoder, SkipWhitespace};
/// const KEY: [u8; 64] = SkipWhitespace(Decoder::Hex).decode(b"
///     9e55d1e1 aa1f455b 8baad9fd f9755036 55f8b359 d542fa7e
///     4ce84106 d625b352 06fac1f2 2240cffd 637ead66 47188429
///     fafda9c9 cb7eae43 386ac17f 61115075
/// ");
/// # assert_eq!(KEY[0], 0x9e);
/// # assert_eq!(KEY[63], 0x75);
/// ```
#[derive(Debug, Clone, Copy)]
pub struct SkipWhitespace(pub Decoder);

impl SkipWhitespace {
    /// Decodes `input` into a byte array.
    ///
    /// # Panics
    ///
    /// - Panics if the provided length is insufficient or too large for `input`.
    /// - Panics if `input` contains invalid chars.
    pub const fn decode<const N: usize>(self, input: &[u8]) -> [u8; N] {
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
/// const PRIVATE_KEY: [u8; 48] = Pem::decode(
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
    pub const fn decode<const N: usize>(input: &[u8]) -> [u8; N] {
        Decoder::Base64.do_decode(input, Some(Skipper::Pem))
    }
}

/// Custom encoding scheme based on a certain alphabet (mapping between a subset of ASCII chars
/// and digits in `0..P`, where `P` is a power of 2).
///
/// # Examples
///
/// ```
/// # use const_decoder::{Decoder, Encoding};
/// // Decoder for Bech32 encoding as specified in
/// // https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki.
/// const BECH32: Decoder = Decoder::Custom(
///     Encoding::new("qpzry9x8gf2tvdw0s3jn54khce6mua7l"),
/// );
///
/// // Sample address from the Bech32 spec excluding the `tb1q` prefix
/// // and the checksum suffix.
/// const SAMPLE_ADDR: [u8; 32] =
///     BECH32.decode(b"rp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q");
/// ```
#[derive(Debug, Clone, Copy)]
pub struct Encoding {
    table: [u8; 128],
    bits_per_char: u8,
}

impl Encoding {
    const NO_MAPPING: u8 = u8::MAX;

    const BASE64: Self =
        Self::new("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/");
    const BASE64_URL: Self =
        Self::new("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_");

    /// Creates an encoding based on the provided `alphabet`: a sequence of ASCII chars
    /// that correspond to digits 0, 1, 2, etc.
    ///
    /// # Panics
    ///
    /// - Panics if `alphabet` does not consist of distinct ASCII chars.
    /// - Panics if `alphabet` length is not 2, 4, 8, 16, 32 or 64.
    #[allow(clippy::cast_possible_truncation)]
    pub const fn new(alphabet: &str) -> Self {
        let bits_per_char = match alphabet.len() {
            2 => 1,
            4 => 2,
            8 => 3,
            16 => 4,
            32 => 5,
            64 => 6,
            _ => panic!("Invalid alphabet length; must be one of 2, 4, 8, 16, 32, or 64"),
        };

        let mut table = [Self::NO_MAPPING; 128];
        let alphabet_bytes = alphabet.as_bytes();
        let mut index = 0;
        while index < alphabet_bytes.len() {
            let byte = alphabet_bytes[index];
            assert!(byte < 0x80, "Non-ASCII alphabet character");
            let byte_idx = byte as usize;
            assert!(
                table[byte_idx] == Self::NO_MAPPING,
                "Alphabet character is mentioned several times"
            );
            table[byte_idx] = index as u8;
            index += 1;
        }

        Self {
            table,
            bits_per_char,
        }
    }

    const fn lookup(&self, ascii_char: u8) -> u8 {
        let mapping = self.table[ascii_char as usize];
        assert!(
            mapping != Self::NO_MAPPING,
            "Character is not present in the alphabet"
        );
        mapping
    }
}

#[cfg(doctest)]
doc_comment::doctest!("../README.md");

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_codec() {
        const KEY: [u8; 4] = Decoder::Hex.decode(b"1234567f");
        assert_eq!(KEY, [0x12, 0x34, 0x56, 0x7f]);
    }

    #[test]
    #[should_panic]
    fn hex_encoding_with_odd_number_of_digits() {
        let _: [u8; 1] = Decoder::Hex.decode(b"012");
    }

    #[test]
    fn hex_codec_with_whitespace() {
        const KEY: [u8; 4] = Decoder::Hex.skip_whitespace().decode(b"12\n34  56\t7f");
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
    fn base64url_codec_in_compile_time() {
        const SAMPLES: &[(&[u8], &[u8])] = &[
            (&Decoder::Base64Url.decode::<6>(b"Pj4-Pz8_"), b">>>???"),
            (&Decoder::Base64Url.decode::<6>(b"PHRlc3Q-"), b"<test>"),
            (
                &Decoder::Base64Url.decode::<10>(b"SGVsbG8_IEhpIQ=="),
                b"Hello? Hi!",
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

    #[test]
    #[should_panic]
    fn mixed_base64_alphabet_leads_to_panic() {
        Decoder::Base64.decode::<6>(b"Pj4-Pz8/");
    }

    const BECH32_ENCODING: Encoding = Encoding::new("qpzry9x8gf2tvdw0s3jn54khce6mua7l");
    const BECH32: Decoder = Decoder::Custom(BECH32_ENCODING);

    // Samples taken from https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki.
    #[test]
    fn bech32_encoding() {
        const SAMPLES: &[(&[u8], &[u8])] = &[
            (
                &BECH32.decode::<20>(b"w508d6qejxtdg4y5r3zarvary0c5xw7k"),
                &Decoder::Hex.decode::<20>(b"751e76e8199196d454941c45d1b3a323f1433bd6"),
            ),
            (
                &BECH32.decode::<32>(b"rp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q"),
                &Decoder::Hex.decode::<32>(
                    b"1863143c14c5166804bd19203356da136c985678cd4d27a1b8c6329604903262",
                ),
            ),
        ];
        for &(actual, expected) in SAMPLES {
            assert_eq!(actual, expected);
        }
    }

    #[test]
    #[should_panic]
    fn bech32_encoding_with_invalid_padding() {
        // The last char `l = 31` is too large.
        let _: [u8; 32] =
            BECH32.decode::<32>(b"rp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3l");
    }

    #[test]
    fn binary_encoding() {
        const BIN: Decoder = Decoder::Custom(Encoding::new("01"));
        assert_eq!(BIN.decode::<1>(b"01101110"), [0b_0110_1110]);
        assert_eq!(
            SkipWhitespace(BIN).decode::<2>(b"0110 1110 1010 0010"),
            [0b_0110_1110, 0b_1010_0010]
        );
    }

    #[test]
    fn octal_encoding() {
        const BASE8: Decoder = Decoder::Custom(Encoding::new("01234567"));
        assert_eq!(BASE8.decode::<1>(b"766"), [0o_76 * 4 + 3]);
        assert_eq!(BASE8.decode::<3>(b"35145661"), [116, 203, 177]);
    }
}
