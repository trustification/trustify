use ring::digest::Context;
use ring::digest::{Digest, SHA256};
use std::io::Read;

pub struct HashingRead<R: Read> {
    inner: R,
    sha256: Context,
}

#[derive(Debug)]
pub struct Hashes {
    pub sha256: Digest,
}

impl<R: Read> HashingRead<R> {
    pub fn new(inner: R) -> Self {
        Self {
            inner,
            sha256: Context::new(&SHA256),
        }
    }

    pub fn hashes(&self) -> Hashes {
        Hashes {
            sha256: self.sha256.clone().finish(),
        }
    }
}

impl<R: Read> Read for &mut HashingRead<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let len = self.inner.read(buf)?;
        self.sha256.update(&buf[0..len]);
        Ok(len)
    }
}
