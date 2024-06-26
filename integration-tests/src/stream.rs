#![cfg(test)]

use bytes::Bytes;
use lzma::LzmaError;
use std::convert::Infallible;

use test_context::futures::{stream, Stream};

/// Take a slice, xa decompress the data and return it as a stream.
///
/// If the decompression fails, that will result in an error on the stream.
pub fn xz_stream(data: &[u8]) -> impl Stream<Item = Result<Bytes, LzmaError>> {
    let result = lzma::decompress(data).map(|data| data.into());
    stream::once(async { result })
}

/// Create a stream from a static BLOB.
pub fn stream(data: &'static [u8]) -> impl Stream<Item = Result<Bytes, Infallible>> {
    stream::once(async move { Ok(Bytes::from_static(data)) })
}
