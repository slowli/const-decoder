use rand::{thread_rng, RngCore};

use const_decoder::{Decoder, Pem};

#[test]
fn reading_from_file_works() {
    const RAW_INPUT: &[u8] = include_bytes!("certificate.crt");
    const CERT: [u8; 888] = Pem::parse(RAW_INPUT);

    let expected = pem::parse(RAW_INPUT).unwrap().contents;
    assert_eq!(CERT, expected.as_slice());
}

fn fuzz_hex_decoder<const N: usize>(samples: usize) {
    let mut rng = thread_rng();
    for _ in 0..samples {
        let mut bytes = [0_u8; N];
        rng.fill_bytes(&mut bytes);

        let encoded = hex::encode(&bytes);
        let decoded = Decoder::Hex.decode::<N>(encoded.as_bytes());
        assert_eq!(decoded, bytes);

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
