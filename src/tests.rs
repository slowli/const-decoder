//! Lower-level tests.

use super::*;

#[test]
fn hex_codec() {
    const KEY: [u8; 4] = Decoder::Hex.decode(b"1234567f");
    assert_eq!(KEY, [0x12, 0x34, 0x56, 0x7f]);
}

#[test]
fn hex_codec_with_macro() {
    const KEY: &[u8] = &decode!(Decoder::Hex, b"1234567f");
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
fn skipping_whitespace_with_macro() {
    const KEY: &[u8] = &decode!(
        Decoder::Hex.skip_whitespace(),
        b"01234567  89abcdef \
          fedcba98  76543210",
    );
    assert_eq!(KEY.len(), 16);
    assert_eq!(KEY[0], 1);
    assert_eq!(KEY[15], 0x10);
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
fn base64_codec_with_macro() {
    const TEST: &[u8] = &decode!(Decoder::Base64, b"VGVzdCBzdHJpbmc=");
    assert_eq!(TEST, b"Test string");
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
#[should_panic(expected = "Character '-' is not present in the alphabet")]
fn mixed_base64_alphabet_leads_to_panic() {
    Decoder::Base64.decode::<6>(b"Pj4-Pz8/");
}

#[test]
#[should_panic(expected = "Invalid alphabet length 5; must be one of 2, 4, 8, 16, 32, or 64")]
fn invalid_alphabet_length() {
    Decoder::custom("what?");
}

#[test]
#[should_panic(expected = "Alphabet 'teß' contains non-ASCII character at position 2")]
fn non_ascii_char_in_alphabet() {
    Decoder::custom("teß");
}

#[test]
#[should_panic(expected = "Alphabet character 'a' is mentioned several times")]
fn duplicate_char_in_alphabet() {
    Decoder::custom("alphabet");
}

#[test]
#[should_panic(expected = "input decodes to 6 bytes, while type inference implies 3.")]
fn input_length_overflow() {
    Decoder::Base64.decode::<3>(b"Pj4+Pz8/");
}

#[test]
#[should_panic(expected = "input decodes to 6 bytes, while type inference implies 16.")]
fn input_length_underflow() {
    Decoder::Base64.decode::<16>(b"Pj4+Pz8/");
}

const BECH32: Decoder = Decoder::custom("qpzry9x8gf2tvdw0s3jn54khce6mua7l");

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
            &Decoder::Hex
                .decode::<32>(b"1863143c14c5166804bd19203356da136c985678cd4d27a1b8c6329604903262"),
        ),
    ];
    for &(actual, expected) in SAMPLES {
        assert_eq!(actual, expected);
    }
}

#[test]
fn bech32_codec_with_macro() {
    const TEST: &[u8] = &decode!(BECH32, b"w508d6qejxtdg4y5r3zarvary0c5xw7k");
    assert_eq!(
        TEST,
        decode!(Decoder::Hex, b"751e76e8199196d454941c45d1b3a323f1433bd6")
    );
}

#[test]
#[should_panic]
fn bech32_encoding_with_invalid_padding() {
    // The last char `l = 31` is too large.
    let _: [u8; 32] = BECH32.decode::<32>(b"rp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3l");
}

#[test]
fn binary_encoding() {
    const BIN: Decoder = Decoder::custom("01");
    assert_eq!(BIN.decode::<1>(b"01101110"), [0b_0110_1110]);
    assert_eq!(
        SkipWhitespace(BIN).decode::<2>(b"0110 1110 1010 0010"),
        [0b_0110_1110, 0b_1010_0010]
    );
}

#[test]
fn octal_encoding() {
    const BASE8: Decoder = Decoder::custom("01234567");
    assert_eq!(BASE8.decode::<1>(b"766"), [0o_76 * 4 + 3]);
    assert_eq!(BASE8.decode::<3>(b"35145661"), [116, 203, 177]);
}

#[test]
fn octal_codec_in_macro() {
    const TEST: &[u8] = &decode!(Decoder::custom("01234567"), b"35145661");
    assert_eq!(TEST, [116, 203, 177]);
}
