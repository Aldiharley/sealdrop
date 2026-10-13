//! SHA-256 helpers used for meta.json, manifests and verification.

use std::fs::File;
use std::io::{self, Read, Write};
use std::path::Path;

use sha2::{Digest, Sha256};

use crate::Result;

/// Writer that hashes everything passing through it.
pub struct HashingWriter<W: Write> {
    inner: W,
    hasher: Sha256,
    bytes: u64,
}

impl<W: Write> HashingWriter<W> {
    pub fn new(inner: W) -> Self {
        Self {
            inner,
            hasher: Sha256::new(),
            bytes: 0,
        }
    }

    /// Returns `(inner, sha256_hex, bytes_written)`.
    pub fn finish(self) -> (W, String, u64) {
        (self.inner, hex::encode(self.hasher.finalize()), self.bytes)
    }
}

impl<W: Write> Write for HashingWriter<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let n = self.inner.write(buf)?;
        self.hasher.update(&buf[..n]);
        self.bytes += n as u64;
        Ok(n)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

pub fn sha256_hex(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data))
}

/// Streams a reader through SHA-256 from its current position. Returns `(hex, size)`.
pub fn sha256_reader(r: &mut impl Read) -> Result<(String, u64)> {
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 1 << 16];
    let mut total = 0u64;
    loop {
        let n = r.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
        total += n as u64;
    }
    Ok((hex::encode(hasher.finalize()), total))
}

/// Streams a file through SHA-256. Returns `(hex, size)`.
pub fn sha256_file(path: &Path) -> Result<(String, u64)> {
    sha256_reader(&mut File::open(path)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn hashing_writer_matches_sha256_of_all_bytes() {
        let mut hw = HashingWriter::new(Vec::new());
        hw.write_all(b"hello ").unwrap();
        hw.write_all(b"world").unwrap();
        let (inner, hash, n) = hw.finish();
        assert_eq!(inner, b"hello world");
        assert_eq!(n, 11);
        assert_eq!(
            hash,
            "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
        );
    }

    #[test]
    fn sha256_file_reads_whole_file() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("a.bin");
        std::fs::write(&p, b"hello world").unwrap();
        let (h, n) = sha256_file(&p).unwrap();
        assert_eq!(n, 11);
        assert_eq!(
            h,
            "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
        );
    }
}
