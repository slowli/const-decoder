//! Decoder wrappers.

use crate::decoder::Decoder;

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
pub(crate) enum Skipper {
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

    pub const fn skip(self, input: &[u8], mut in_index: usize) -> usize {
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
