//! `Decoder` and closely related types.

use compile_fmt::{compile_assert, compile_panic, fmt, clip};

use crate::wrappers::{SkipWhitespace, Skipper};

/// Custom encoding scheme based on a certain alphabet (mapping between a subset of ASCII chars
/// and digits in `0..P`, where `P` is a power of 2).
///
/// # Examples
///
/// ```
/// # use const_decoder::Decoder;
/// // Decoder for Bech32 encoding as specified in
/// // https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki.
/// const BECH32: Decoder = Decoder::custom("qpzry9x8gf2tvdw0s3jn54khce6mua7l");
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
            other => compile_panic!(
                "Invalid alphabet length ", other => fmt::<usize>(),
                "; must be one of 2, 4, 8, 16, 32, or 64"
            ),
        };

        let mut table = [Self::NO_MAPPING; 128];
        let alphabet_bytes = alphabet.as_bytes();
        let mut index = 0;
        while index < alphabet_bytes.len() {
            let byte = alphabet_bytes[index];
            compile_assert!(
                byte < 0x80,
                "Alphabet '", alphabet => clip(64, ""), "' contains non-ASCII character at ",
                index => fmt::<usize>()
            );
            let byte_idx = byte as usize;
            compile_assert!(
                table[byte_idx] == Self::NO_MAPPING,
                "Alphabet character '", byte as char => fmt::<char>(), "' is mentioned several times"
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
        compile_assert!(
            mapping != Self::NO_MAPPING,
            "Character '", ascii_char as char => fmt::<char>(), "' is not present in the alphabet"
        );
        mapping
    }
}

/// Internal state of the hexadecimal decoder.
#[derive(Debug, Clone, Copy)]
struct HexDecoderState(Option<u8>);

impl HexDecoderState {
    const fn byte_value(val: u8) -> u8 {
        match val {
            b'0'..=b'9' => val - b'0',
            b'A'..=b'F' => val - b'A' + 10,
            b'a'..=b'f' => val - b'a' + 10,
            _ => compile_panic!(
                "Invalid character '", val as char => fmt::<char>(), "' in input; expected a hex digit"
            ),
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
    /// Creates a new decoder with a custom alphabet.
    ///
    /// # Panics
    ///
    /// Panics in the same situations as [`Encoding::new()`].
    pub const fn custom(alphabet: &str) -> Self {
        Self::Custom(Encoding::new(alphabet))
    }

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

    pub(crate) const fn do_decode<const N: usize>(
        self,
        input: &[u8],
        skipper: Option<Skipper>,
    ) -> [u8; N] {
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
                if out_index < N {
                    bytes[out_index] = byte;
                }
                out_index += 1;
            }
            in_index += 1;
        }

        compile_assert!(
            out_index <= N,
            "Output overflow: the input decodes to ", out_index => fmt::<usize>(),
            " bytes, while type inference implies ",  N => fmt::<usize>(), ". \
            Either fix the input or change the output buffer length correspondingly"
        );
        compile_assert!(
            out_index == N,
            "Output underflow: the input decodes to ", out_index => fmt::<usize>(),
            " bytes, while type inference implies ", N => fmt::<usize>(), ". \
            Either fix the input or change the output buffer length correspondingly"
        );

        assert!(
            state.is_final(),
            "Left-over state after processing input. This usually means that the input \
             is incorrect (e.g., an odd number of hex digits)."
        );
        bytes
    }
}
