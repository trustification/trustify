use ring::digest::Algorithm;
use ring::digest::Context;
use ring::digest::{Digest, SHA384};
use std::io::Read;

pub struct HashingRead<R: Read> {
    inner: R,
    ctx: Context,
}

impl<R: Read> HashingRead<R> {
    /// Uses SHA-384 as the default hashing algorithm
    pub fn new(inner: R) -> Self {
        Self::new_with_algorithm(inner, &SHA384)
    }

    pub fn new_with_algorithm(inner: R, algorithm: &'static Algorithm) -> Self {
        Self {
            inner,
            ctx: Context::new(algorithm),
        }
    }

    /// Returns the hash digest of the data read so far
    pub fn hash(&self) -> Digest {
        self.ctx.clone().finish()
    }

    /// Finishes reading all data from the inner reader and returns the hash digest
    pub fn finish(mut self) -> std::io::Result<Digest> {
        self.read_to_end(&mut Vec::new())?;
        Ok(self.ctx.finish())
    }
}

impl<R: Read> Read for HashingRead<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let len = self.inner.read(buf)?;
        self.ctx.update(&buf[0..len]);
        Ok(len)
    }
}

#[cfg(test)]
mod test {
    use super::HashingRead;
    use rand::RngCore;
    use ring::digest::{digest, SHA384};
    use std::io::Read;

    fn rand_bytes() -> [u8; 1024] {
        let mut buf = [0u8; 1024];
        rand::thread_rng().fill_bytes(&mut buf);
        buf
    }

    /// HashingRead should read data correctly
    #[test]
    fn read() {
        let data = rand_bytes();
        let mut reader = HashingRead::new(data.as_slice());
        let mut buf = Vec::new();
        reader.read_to_end(&mut buf).unwrap();
        assert_eq!(buf, data);
    }

    /// HashingRead should return the correct hash when finish() is called
    #[test]
    fn default_hash() {
        let data = rand_bytes();
        let reader = HashingRead::new(data.as_slice());
        let digest_res = reader.finish().unwrap();
        let digest_bytes = digest_res.as_ref();

        let expected_digest = digest(&SHA384, &data);
        let expected_digest_bytes = expected_digest.as_ref();
        assert_eq!(digest_bytes, expected_digest_bytes);
    }

    /// HashingRead should consume the reader entirely and return the hash when finish() is called
    #[test]
    fn finish_hash() {
        let data = rand_bytes();
        let reader = HashingRead::new(data.as_slice());
        let digest_res = reader.finish().unwrap(); // This should !!! consume the reader entirely !!! and return the digest
        let digest_bytes = digest_res.as_ref();

        let expected_digest = digest(&SHA384, &data);
        let expected_digest_bytes = expected_digest.as_ref();
        assert_eq!(digest_bytes, expected_digest_bytes);
    }

    /// HashingRead should return the hash of the data read so far when hash() is called
    #[test]
    fn intermediate_hash() {
        let data = rand_bytes();
        let mut reader = HashingRead::new(data.as_ref());
        let mut buf = Vec::new();
        let num_bytes = reader.read(&mut buf).unwrap();
        let digest_res = reader.hash();
        let digest_bytes = digest_res.as_ref();

        let expected_digest = digest(&SHA384, &buf[0..num_bytes]);
        let expected_digest_bytes = expected_digest.as_ref();
        assert_eq!(digest_bytes, expected_digest_bytes);
    }
}
