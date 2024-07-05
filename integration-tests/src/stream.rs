#![cfg(test)]

use bytes::Bytes;
use std::convert::Infallible;
use std::io::Read;
use test_context::futures::{stream, Stream};
use xz2::read::XzDecoder;

/// Take a slice, xa decompress the data and return it as a stream.
///
/// If the decompression fails, that will result in an error on the stream.
pub fn xz_stream(data: &[u8]) -> impl Stream<Item = Result<Bytes, std::io::Error>> {
    let mut buffer: Vec<u8> = Vec::new();
    let mut reader = XzDecoder::new(data);
    let result = reader.read_to_end(&mut buffer).map(|_| buffer.into());
    stream::once(async { result })
}

/// Create a stream from a static BLOB.
pub fn stream(data: &'static [u8]) -> impl Stream<Item = Result<Bytes, Infallible>> {
    stream::once(async move { Ok(Bytes::from_static(data)) })
}
