//! `decode!` macro and the associated helper types.

#![allow(missing_docs)] // FIXME

use crate::{
    decoder::Decoder,
    wrappers::{Pem, SkipWhitespace, Skipper},
};

#[macro_export]
macro_rules! decode {
    ($decoder:expr, $bytes:expr $(,)?) => {{
        const __OUTPUT_LEN: usize = $crate::DecoderWrapper($decoder).decode_len($bytes);
        $crate::DecoderWrapper($decoder).decode::<__OUTPUT_LEN>($bytes) as [u8; __OUTPUT_LEN]
    }};
}

#[derive(Debug)]
pub struct DecoderWrapper<T>(pub T);

impl DecoderWrapper<Decoder> {
    pub const fn decode_len(&self, input: &[u8]) -> usize {
        self.0.do_decode_len(input, None)
    }

    pub const fn decode<const N: usize>(self, input: &[u8]) -> [u8; N] {
        self.0.decode(input)
    }
}

impl DecoderWrapper<SkipWhitespace> {
    pub const fn decode_len(&self, input: &[u8]) -> usize {
        let Self(SkipWhitespace(decoder)) = self;
        decoder.do_decode_len(input, Some(Skipper::Whitespace))
    }

    pub const fn decode<const N: usize>(self, input: &[u8]) -> [u8; N] {
        self.0.decode(input)
    }
}

impl DecoderWrapper<Pem> {
    pub const fn decode_len(&self, input: &[u8]) -> usize {
        Decoder::Base64.do_decode_len(input, Some(Skipper::Pem))
    }

    pub const fn decode<const N: usize>(self, input: &[u8]) -> [u8; N] {
        Pem::decode(input)
    }
}
