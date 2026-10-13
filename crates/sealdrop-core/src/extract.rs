//! Hardened tar extraction (spec section 7).

use std::collections::{HashMap, HashSet};
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

use crate::hashing::HashingWriter;
use crate::pack::{FileEntry, Meta, META_FORMAT, META_PATH, PAYLOAD_PREFIX};
use crate::{Error, Result};

pub const META_MAX_BYTES: u64 = 1024 * 1024;

#[derive(Debug, Clone)]
pub struct Limits {
    pub max_entries: u64,
    pub max_bytes: u64,
    pub max_file_bytes: u64,
    /// Largest tar extension header (`L`, `K`, `x`, `g`) the tar crate may buffer.
    pub max_header_bytes: u64,
    /// Largest raw tar stream consumed, headers and padding included.
    pub max_input_bytes: u64,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_entries: 100_000,
            max_bytes: 64 << 30,
            max_file_bytes: 64 << 30,
            max_header_bytes: 1 << 20,
            max_input_bytes: (64 << 30) + (1 << 30),
        }
    }
}

#[derive(Debug, Clone, thiserror::Error, PartialEq, Eq)]
pub enum ExtractError {
    #[error("forbidden entry type for {0}")]
    ForbiddenEntry(String),
    #[error("bad path {0}")]
    BadPath(String),
    #[error("first entry must be sealdrop/meta.json")]
    MetaMissing,
    #[error("meta.json too large")]
    MetaTooLarge,
    #[error("meta.json invalid: {0}")]
    MetaInvalid(String),
    #[error("too many entries")]
    TooManyEntries,
    #[error("too many bytes")]
    TooManyBytes,
    #[error("hash mismatch for {0}")]
    HashMismatch(String),
    #[error("file listed in meta.json missing from archive: {0}")]
    MissingFile(String),
    #[error("file not listed in meta.json: {0}")]
    UnlistedFile(String),
    #[error("entry root {0} does not match meta root")]
    WrongRoot(String),
    #[error("duplicate path in meta.json: {0}")]
    DuplicatePath(String),
    #[error("tar extension header of {0} bytes exceeds the limit")]
    HeaderTooLarge(u64),
}

#[derive(Debug, Clone)]
pub struct ExtractReport {
    pub root: PathBuf,
    pub files: usize,
    pub bytes: u64,
    pub meta: Meta,
}

const WINDOWS_RESERVED: &[&str] = &[
    "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8",
    "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
];

/// Validates a tar entry path and returns it relative to `sealdrop/payload/`.
pub fn check_path(p: &str) -> std::result::Result<String, ExtractError> {
    let bad = || ExtractError::BadPath(p.to_string());
    if p.contains('\0') || p.contains('\\') || p.contains(':') || p.starts_with('/') {
        return Err(bad());
    }
    let rel = p.strip_prefix(PAYLOAD_PREFIX).ok_or_else(bad)?;
    if rel.is_empty() {
        return Err(bad());
    }
    for comp in rel.split('/') {
        if comp.is_empty() || comp == "." || comp == ".." {
            return Err(bad());
        }
        // Windows silently strips trailing spaces and dots, so `CON ` aliases `CON` and
        // `a.` aliases `a`.
        if comp.ends_with(' ') || comp.ends_with('.') {
            return Err(bad());
        }
        // Control characters and characters Windows forbids in names.
        if comp
            .bytes()
            .any(|b| b < 0x20 || matches!(b, b'<' | b'>' | b'"' | b'|' | b'?' | b'*'))
        {
            return Err(bad());
        }
        let stem = comp.split('.').next().unwrap_or("").to_ascii_uppercase();
        if WINDOWS_RESERVED.contains(&stem.as_str()) {
            return Err(bad());
        }
    }
    Ok(rel.to_string())
}

fn entry_path_string(
    entry: &tar::Entry<'_, impl Read>,
) -> std::result::Result<String, ExtractError> {
    let p = entry
        .path()
        .map_err(|e| ExtractError::BadPath(e.to_string()))?;
    // Non-UTF-8 names are refused rather than lossily converted.
    p.to_str()
        .map(str::to_owned)
        .ok_or_else(|| ExtractError::BadPath(p.to_string_lossy().into_owned()))
}

fn forbidden(what: &str) -> io::Error {
    io::Error::other(ExtractError::ForbiddenEntry(what.to_string()))
}

/// Length of the zero padding that follows a payload of `size` bytes.
fn padding(size: u64) -> u64 {
    (512 - size % 512) % 512
}

/// Decodes a tar numeric size field the way the tar crate does: GNU base-256 when the
/// high bit is set, otherwise NUL-terminated, space-trimmed octal.
fn parse_size(field: &[u8]) -> io::Result<u64> {
    if field[0] & 0x80 != 0 {
        let tail = &field[field.len() - 8..];
        return Ok(tail.iter().fold(0u64, |acc, b| (acc << 8) | u64::from(*b)));
    }
    let digits = field
        .iter()
        .position(|b| *b == 0)
        .map_or(field, |i| &field[..i]);
    let s = std::str::from_utf8(digits).map_err(|_| io::Error::other("bad tar size field"))?;
    u64::from_str_radix(s.trim(), 8).map_err(|_| io::Error::other("bad tar size field"))
}

/// Refuses a PAX `x` payload carrying a `size=` record. The tar crate would apply that
/// size to the next member, which the header-size bookkeeping here cannot see. Matching
/// the bytes is deliberately broader than parsing the records, so it cannot disagree
/// with the tar crate about which records exist.
fn check_pax(buf: &[u8]) -> io::Result<()> {
    if buf.windows(5).any(|w| w == b"size=") {
        return Err(forbidden("pax size override"));
    }
    Ok(())
}

/// Watches the raw tar stream and refuses input the tar crate would otherwise buffer
/// without bound. The tar crate reads sequentially, so every byte it consumes passes
/// through here first.
///
/// Header boundaries are tracked the way the tar crate tracks them: a 512-byte header,
/// then the declared size padded to 512. Inputs whose effective size can differ from
/// the header field (GNU sparse `S`, PAX `size=`) are refused, so the two views agree.
struct GuardedReader<R: Read> {
    inner: R,
    limits_header: u64,
    limits_input: u64,
    read_total: u64,
    /// Payload bytes (and padding) still to skip before the next header.
    skip: u64,
    /// Bytes of a PAX `x` payload still to collect and inspect.
    pax_left: u64,
    pax_buf: Vec<u8>,
    header_buf: [u8; 512],
    header_fill: usize,
}

impl<R: Read> GuardedReader<R> {
    fn new(inner: R, max_header_bytes: u64, max_input_bytes: u64) -> Self {
        Self {
            inner,
            limits_header: max_header_bytes,
            limits_input: max_input_bytes,
            read_total: 0,
            skip: 0,
            pax_left: 0,
            pax_buf: Vec::new(),
            header_buf: [0; 512],
            header_fill: 0,
        }
    }

    /// Called once per complete 512-byte block that is at a header boundary.
    fn on_header(&mut self) -> io::Result<()> {
        let h = self.header_buf;
        if h.iter().all(|b| *b == 0) {
            return Ok(()); // end-of-archive block
        }
        let typeflag = h[156];
        let size = parse_size(&h[124..136])?;
        match typeflag {
            b'L' | b'K' | b'x' | b'g' if size > self.limits_header => {
                Err(io::Error::other(ExtractError::HeaderTooLarge(size)))
            }
            b'g' => Err(forbidden("pax global header")),
            b'x' => {
                self.pax_left = size;
                self.skip = padding(size);
                Ok(())
            }
            b'S' => Err(forbidden("gnu sparse entry")),
            _ => {
                self.skip = size.saturating_add(padding(size));
                Ok(())
            }
        }
    }
}

impl<R: Read> Read for GuardedReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.read_total += n as u64;
        if self.read_total > self.limits_input {
            return Err(io::Error::other(ExtractError::TooManyBytes));
        }
        let mut i = 0;
        while i < n {
            if self.pax_left > 0 {
                let k = (n - i).min(usize::try_from(self.pax_left).unwrap_or(usize::MAX));
                self.pax_buf.extend_from_slice(&buf[i..i + k]);
                self.pax_left -= k as u64;
                i += k;
                if self.pax_left == 0 {
                    check_pax(&self.pax_buf)?;
                    self.pax_buf.clear();
                }
            } else if self.skip > 0 {
                let k = (n - i).min(usize::try_from(self.skip).unwrap_or(usize::MAX));
                self.skip -= k as u64;
                i += k;
            } else {
                let take = (512 - self.header_fill).min(n - i);
                self.header_buf[self.header_fill..self.header_fill + take]
                    .copy_from_slice(&buf[i..i + take]);
                self.header_fill += take;
                i += take;
                if self.header_fill == 512 {
                    self.header_fill = 0;
                    self.on_header()?;
                }
            }
        }
        Ok(n)
    }
}

/// Recovers an `ExtractError` that travelled through the tar crate inside an `io::Error`.
fn unwrap_io(e: io::Error) -> Error {
    let found = e
        .get_ref()
        .and_then(|inner| inner.downcast_ref::<ExtractError>())
        .cloned();
    match found {
        Some(x) => Error::Extract(x),
        None => Error::Io(e),
    }
}

/// Extracts a sealdrop tar stream into `out_dir/<root>`, verifying every file hash.
pub fn extract<R: Read>(
    r: R,
    out_dir: &Path,
    limits: &Limits,
    overwrite: bool,
) -> Result<ExtractReport> {
    let guarded = GuardedReader::new(r, limits.max_header_bytes, limits.max_input_bytes);
    let mut archive = tar::Archive::new(guarded);
    let mut entries = archive.entries()?;

    // 1. meta.json must be first.
    let first = entries
        .next()
        .ok_or(ExtractError::MetaMissing)?
        .map_err(unwrap_io)?;
    if entry_path_string(&first)? != META_PATH || !first.header().entry_type().is_file() {
        return Err(ExtractError::MetaMissing.into());
    }
    if first.size() > META_MAX_BYTES {
        return Err(ExtractError::MetaTooLarge.into());
    }
    let mut meta_bytes = Vec::new();
    first
        .take(META_MAX_BYTES + 1)
        .read_to_end(&mut meta_bytes)
        .map_err(unwrap_io)?;
    if meta_bytes.len() as u64 > META_MAX_BYTES {
        return Err(ExtractError::MetaTooLarge.into());
    }
    let meta: Meta = serde_json::from_slice(&meta_bytes)
        .map_err(|e| ExtractError::MetaInvalid(e.to_string()))?;
    if meta.format != META_FORMAT {
        return Err(ExtractError::MetaInvalid(format!("unknown format {}", meta.format)).into());
    }
    if meta.root.contains('/') {
        return Err(ExtractError::MetaInvalid(format!("root {} contains '/'", meta.root)).into());
    }
    check_path(&format!("{PAYLOAD_PREFIX}{}", meta.root))?;
    for f in &meta.files {
        let rel = check_path(&format!("{PAYLOAD_PREFIX}{}", f.path))?;
        if rel.split('/').next() != Some(meta.root.as_str()) {
            return Err(ExtractError::WrongRoot(f.path.clone()).into());
        }
    }
    let mut expected: HashMap<&str, &FileEntry> = HashMap::new();
    for f in &meta.files {
        if expected.insert(f.path.as_str(), f).is_some() {
            return Err(ExtractError::DuplicatePath(f.path.clone()).into());
        }
    }

    // 2. Temp dir inside out_dir so the final rename is atomic on the same volume.
    fs::create_dir_all(out_dir)?;
    let final_path = out_dir.join(&meta.root);
    if final_path.exists() && !overwrite {
        return Err(Error::Exists(final_path));
    }
    let tmp = tempfile::Builder::new()
        .prefix(".sealdrop-")
        .tempdir_in(out_dir)?;

    let mut n_entries = 1u64;
    let mut n_bytes = 0u64;
    let mut seen: HashSet<String> = HashSet::new();

    for entry in entries {
        let mut entry = entry.map_err(unwrap_io)?;
        n_entries += 1;
        if n_entries > limits.max_entries {
            return Err(ExtractError::TooManyEntries.into());
        }
        let raw = entry_path_string(&entry)?;
        let rel = check_path(&raw)?;
        if rel.split('/').next() != Some(meta.root.as_str()) {
            return Err(ExtractError::WrongRoot(rel).into());
        }
        let dest = tmp.path().join(&rel);
        let et = entry.header().entry_type();
        if et.is_dir() {
            fs::create_dir_all(&dest)?;
            continue;
        }
        if !et.is_file() {
            return Err(ExtractError::ForbiddenEntry(rel).into());
        }
        let fe = *expected
            .get(rel.as_str())
            .ok_or_else(|| ExtractError::UnlistedFile(rel.clone()))?;
        let size = entry.size();
        if entry.header().size()? != size {
            return Err(ExtractError::HashMismatch(rel).into());
        }
        if size > limits.max_file_bytes {
            return Err(ExtractError::TooManyBytes.into());
        }
        if size != fe.size {
            return Err(ExtractError::HashMismatch(rel).into());
        }
        n_bytes = n_bytes
            .checked_add(size)
            .ok_or(ExtractError::TooManyBytes)?;
        if n_bytes > limits.max_bytes {
            return Err(ExtractError::TooManyBytes.into());
        }
        if let Some(parent) = dest.parent() {
            fs::create_dir_all(parent)?;
        }
        let mut hw = HashingWriter::new(File::create(&dest)?);
        io::copy(&mut entry.by_ref().take(size), &mut hw).map_err(unwrap_io)?;
        let (mut f, hash, written) = hw.finish();
        f.flush()?;
        if written != size || hash != fe.sha256 {
            return Err(ExtractError::HashMismatch(rel).into());
        }
        seen.insert(rel);
    }

    for f in &meta.files {
        if !seen.contains(&f.path) {
            return Err(ExtractError::MissingFile(f.path.clone()).into());
        }
    }

    // 3. Move into place.
    let staged = tmp.path().join(&meta.root);
    if overwrite && final_path.exists() {
        if final_path.is_dir() {
            fs::remove_dir_all(&final_path)?;
        } else {
            fs::remove_file(&final_path)?;
        }
    }
    fs::rename(&staged, &final_path)?;
    Ok(ExtractReport {
        root: final_path,
        files: seen.len(),
        bytes: n_bytes,
        meta,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_normal_payload_paths() {
        assert_eq!(
            check_path("sealdrop/payload/report.pdf").unwrap(),
            "report.pdf"
        );
        assert_eq!(
            check_path("sealdrop/payload/findings/sub/b.bin").unwrap(),
            "findings/sub/b.bin"
        );
    }

    #[test]
    fn rejects_bad_paths() {
        for bad in [
            "/etc/passwd",
            "sealdrop/payload/../x",
            "sealdrop/payload/a/../../x",
            "sealdrop/payload/./x",
            "sealdrop/payload//x",
            "sealdrop/payload/a\\b",
            "sealdrop/payload/c:x",
            "sealdrop/payload/CON",
            "sealdrop/payload/dir/lpt1.txt",
            "other/payload/x",
            "sealdrop/payload/",
            "sealdrop/payload/a\0b",
            "sealdrop/payload/CON ",
            "sealdrop/payload/a.",
            "sealdrop/payload/a. /b",
            "sealdrop/payload/x<y",
            "sealdrop/payload/x\u{7}y",
        ] {
            assert!(check_path(bad).is_err(), "should reject {bad:?}");
        }
    }
}
