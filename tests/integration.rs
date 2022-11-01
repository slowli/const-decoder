use bech32::{ToBase32, Variant};
use rand::{thread_rng, RngCore};

use const_decoder::{Decoder, Pem};

#[test]
fn reading_from_file_works() {
    const RAW_INPUT: &[u8] = include_bytes!("certificate.crt");
    const CERT: [u8; 888] = Pem::decode(RAW_INPUT);

    let expected = pem::parse(RAW_INPUT).unwrap().contents;
    assert_eq!(CERT, expected.as_slice());
}

fn fuzz_hex_decoder<const N: usize>(samples: usize) {
    const CUSTOM_HEX: Decoder = Decoder::custom("0123456789abcdef");

    let mut rng = thread_rng();
    for _ in 0..samples {
        let mut bytes = [0_u8; N];
        rng.fill_bytes(&mut bytes);

        let encoded = hex::encode(&bytes);
        let decoded = Decoder::Hex.decode::<N>(encoded.as_bytes());
        assert_eq!(decoded, bytes);

        let decoded_custom = CUSTOM_HEX.decode::<N>(encoded.as_bytes());
        assert_eq!(decoded_custom, bytes);

        let encoded_upper_case = hex::encode_upper(&bytes);
        let decoded_upper_case = Decoder::Hex.decode::<N>(encoded_upper_case.as_bytes());
        assert_eq!(decoded_upper_case, bytes);
    }
}

#[test]
fn hex_decoder_mini_fuzz() {
    fuzz_hex_decoder::<1>(50);
    fuzz_hex_decoder::<8>(10_000);
    fuzz_hex_decoder::<16>(10_000);
    fuzz_hex_decoder::<64>(10_000);
    fuzz_hex_decoder::<1024>(10_000);
}

fn fuzz_base64_decoder<const N: usize>(samples: usize) {
    let mut rng = thread_rng();
    for _ in 0..samples {
        let mut bytes = [0_u8; N];
        rng.fill_bytes(&mut bytes);

        let encoded = base64::encode(&bytes);
        let decoded = Decoder::Base64.decode::<N>(encoded.as_bytes());
        assert_eq!(decoded, bytes);

        let encoded_no_pad = base64::encode_config(&bytes, base64::STANDARD_NO_PAD);
        let decoded_no_pad = Decoder::Base64.decode::<N>(encoded_no_pad.as_bytes());
        assert_eq!(decoded_no_pad, bytes);
    }
}

#[test]
fn base64_decoder_mini_fuzz() {
    fuzz_base64_decoder::<1>(50);
    fuzz_base64_decoder::<8>(10_000);
    fuzz_base64_decoder::<16>(10_000);
    fuzz_base64_decoder::<24>(10_000);
    fuzz_base64_decoder::<64>(10_000);
    fuzz_base64_decoder::<1024>(10_000);
}

fn fuzz_base64url_decoder<const N: usize>(samples: usize) {
    let mut rng = thread_rng();
    for _ in 0..samples {
        let mut bytes = [0_u8; N];
        rng.fill_bytes(&mut bytes);

        let encoded = base64::encode_config(&bytes, base64::URL_SAFE);
        let decoded = Decoder::Base64Url.decode::<N>(encoded.as_bytes());
        assert_eq!(decoded, bytes);

        let encoded_no_pad = base64::encode_config(&bytes, base64::URL_SAFE_NO_PAD);
        let decoded_no_pad = Decoder::Base64Url.decode::<N>(encoded_no_pad.as_bytes());
        assert_eq!(decoded_no_pad, bytes);
    }
}

#[test]
fn base64url_decoder_mini_fuzz() {
    fuzz_base64url_decoder::<1>(50);
    fuzz_base64url_decoder::<8>(10_000);
    fuzz_base64url_decoder::<16>(10_000);
    fuzz_base64url_decoder::<24>(10_000);
    fuzz_base64url_decoder::<64>(10_000);
    fuzz_base64url_decoder::<1024>(10_000);
}

const BECH32: Decoder = Decoder::custom("qpzry9x8gf2tvdw0s3jn54khce6mua7l");

fn fuzz_bech32_decoder<const N: usize>(samples: usize) {
    let mut rng = thread_rng();
    for _ in 0..samples {
        let mut bytes = [0_u8; N];
        rng.fill_bytes(&mut bytes);

        let encoded = bech32::encode("bc", bytes.to_base32(), Variant::Bech32).unwrap();
        let data_part = &encoded.as_bytes()[3..(encoded.len() - 6)];
        let decoded = BECH32.decode::<N>(data_part);
        assert_eq!(decoded, bytes);
    }
}

#[test]
fn bech32_decoder_mini_fuzz() {
    fuzz_bech32_decoder::<1>(50);
    fuzz_bech32_decoder::<8>(10_000);
    fuzz_bech32_decoder::<16>(10_000);
    fuzz_bech32_decoder::<24>(10_000);
    fuzz_bech32_decoder::<64>(10_000);
}
