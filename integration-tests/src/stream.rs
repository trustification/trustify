#![cfg(test)]

use bytes::Bytes;
use std::convert::Infallible;
use std::io::Error;
use std::io::ErrorKind;
use std::io::Read;
use test_context::futures::{stream, Stream};
use xz2::read::XzDecoder;

/// Take a slice, xa decompress the data and return it as a stream.
///
/// If the decompression fails, that will result in an error on the stream.
pub fn xz_stream(data: &[u8]) -> impl Stream<Item = Result<Bytes, Error>> {
    let mut result = XzDecoder::new(data);
    let mut extracted_content = Vec::new();
    match result.read_to_end(&mut extracted_content) {
        Ok(_) => (),
        Err(e) => {
            Error::new(ErrorKind::Other, e);
        }
    }
    stream::once(async { Ok(Bytes::from(extracted_content)) })
}

/// Create a stream from a static BLOB.
pub fn stream(data: &'static [u8]) -> impl Stream<Item = Result<Bytes, Infallible>> {
    stream::once(async move { Ok(Bytes::from_static(data)) })
}
