//! Bounded scan of an age header (spec 10.3) to learn which stanza types are present
//! before any decryption or network call.

use std::fs::File;
use std::io::Read;
use std::path::Path;

use base64::prelude::{Engine, BASE64_STANDARD, BASE64_STANDARD_NO_PAD};

use crate::{Error, Result};

pub const HEADER_MAX: usize = 64 * 1024;

#[derive(Debug, Clone)]
pub struct ReleaseArgs {
    pub release_id: String,
    pub service: String,
    pub nonce_b64: String,
    pub unlock_token_b64: String,
}

#[derive(Debug, Clone)]
pub struct Probe {
    pub armored: bool,
    pub tags: Vec<String>,
    pub needs_passphrase: bool,
    pub release: Option<ReleaseArgs>,
}

/// Read at most `HEADER_MAX + 1` bytes of `path` and probe them.
pub fn probe(path: &Path) -> Result<Probe> {
    let mut buf = Vec::with_capacity(HEADER_MAX + 1);
    File::open(path)?
        .take(HEADER_MAX as u64 + 1)
        .read_to_end(&mut buf)?;
    probe_bytes(&buf)
}

pub fn probe_bytes(buf: &[u8]) -> Result<Probe> {
    // The armor spec allows whitespace before the BEGIN line; `decrypt_reader` skips it too.
    let buf = buf.trim_ascii_start();
    let armored = buf.starts_with(b"-----BEGIN AGE ENCRYPTED FILE-----");
    let text: Vec<u8> = if armored {
        // Work on bytes: the input is untrusted and may be cut off at any point.
        let mut ended = false;
        let mut body: Vec<u8> = Vec::new();
        for line in buf.split(|b| *b == b'\n').skip(1) {
            let line = line.trim_ascii();
            if line.starts_with(b"-") {
                // `-----END AGE ENCRYPTED FILE-----`, or a cut-off prefix of it.
                ended = true;
                break;
            }
            if !line
                .iter()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'='))
            {
                return Err(Error::Other(
                    "armor body contains invalid characters".into(),
                ));
            }
            body.extend_from_slice(line);
        }
        if !ended {
            // The input was cut off mid-armor (a long file read only up to HEADER_MAX):
            // keep whole base64 quanta only.
            body.truncate(body.len() / 4 * 4);
        }
        BASE64_STANDARD
            .decode(&body)
            .or_else(|_| BASE64_STANDARD_NO_PAD.decode(&body))
            .map_err(|_| Error::Other("armor decode failed".into()))?
    } else {
        buf.to_vec()
    };
    let end = find(&text, b"\n---")
        .ok_or_else(|| Error::Other("age header not found within 64 KiB".into()))?;
    if end > HEADER_MAX {
        return Err(Error::Other("age header too large".into()));
    }
    let header = String::from_utf8_lossy(&text[..end]);
    if header.split('\n').next() != Some("age-encryption.org/v1") {
        return Err(Error::Other("not an age file".into()));
    }
    let mut tags = Vec::new();
    let mut release = None;
    for line in header.lines() {
        if let Some(rest) = line.strip_prefix("-> ") {
            let parts: Vec<&str> = rest.split(' ').collect();
            let tag = parts[0].to_string();
            if tag == crate::release::TAG && parts.len() == 5 {
                let service = BASE64_STANDARD_NO_PAD
                    .decode(parts[2])
                    .ok()
                    .and_then(|b| String::from_utf8(b).ok())
                    .ok_or_else(|| Error::Other("bad release stanza".into()))?;
                release = Some(ReleaseArgs {
                    release_id: parts[1].to_string(),
                    service,
                    nonce_b64: parts[3].to_string(),
                    unlock_token_b64: parts[4].to_string(),
                });
            }
            tags.push(tag);
        }
    }
    let needs_passphrase = tags
        .iter()
        .any(|t| t == "scrypt" || t == crate::argon2id::TAG);
    Ok(Probe {
        armored,
        tags,
        needs_passphrase,
        release,
    })
}

fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn detects_scrypt_and_armor() {
        let pass = age::secrecy::SecretString::from("p".to_string());
        for armor in [false, true] {
            let r: Vec<Box<dyn age::Recipient + Send>> = vec![Box::new(
                crate::crypt::scrypt_recipient(pass.clone(), 10).unwrap(),
            )];
            let mut w = crate::crypt::encrypt_writer(Vec::new(), &r, armor).unwrap();
            w.write_all(b"x").unwrap();
            let ct = w.finish().unwrap();
            let p = probe_bytes(&ct).unwrap();
            assert_eq!(p.armored, armor);
            assert_eq!(p.tags, vec!["scrypt"]);
            assert!(p.needs_passphrase);
            assert!(p.release.is_none());
        }
    }

    #[test]
    fn leading_whitespace_before_armor_is_tolerated() {
        let pass = age::secrecy::SecretString::from("p".to_string());
        let r: Vec<Box<dyn age::Recipient + Send>> =
            vec![Box::new(crate::crypt::scrypt_recipient(pass, 10).unwrap())];
        let mut w = crate::crypt::encrypt_writer(Vec::new(), &r, true).unwrap();
        w.write_all(b"x").unwrap();
        let mut ct = b"  \n\t".to_vec();
        ct.extend(w.finish().unwrap());
        let p = probe_bytes(&ct).unwrap();
        assert!(p.armored);
        assert_eq!(p.tags, vec!["scrypt"]);
    }

    #[test]
    fn rejects_oversized_header() {
        let mut junk = b"age-encryption.org/v1\n".to_vec();
        junk.extend(std::iter::repeat_n(b'a', HEADER_MAX + 10));
        assert!(probe_bytes(&junk).is_err());
    }

    #[test]
    fn truncated_armor_still_probes() {
        // A header of ~250 x25519 stanzas plus a payload pushes the armored file past
        // HEADER_MAX; `probe` only reads HEADER_MAX + 1 bytes of it.
        let r: Vec<Box<dyn age::Recipient + Send>> = (0..250)
            .map(|_| {
                Box::new(age::x25519::Identity::generate().to_public())
                    as Box<dyn age::Recipient + Send>
            })
            .collect();
        let mut w = crate::crypt::encrypt_writer(Vec::new(), &r, true).unwrap();
        w.write_all(&vec![7u8; 40_000]).unwrap();
        let ct = w.finish().unwrap();
        assert!(ct.len() > HEADER_MAX + 1);
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("big.age");
        std::fs::write(&path, &ct).unwrap();
        let p = probe(&path).unwrap();
        assert!(p.armored);
        // age may add a grease stanza, so count the X25519 ones.
        assert_eq!(p.tags.iter().filter(|t| *t == "X25519").count(), 250);
        assert!(!p.needs_passphrase);
    }

    #[test]
    fn rejects_non_age_input() {
        assert!(probe_bytes(
            b"hello world
---"
        )
        .is_err());
    }

    #[test]
    fn armored_body_with_non_ascii_is_an_error_not_a_panic() {
        let junk = "-----BEGIN AGE ENCRYPTED FILE-----\nabc\u{e9}\n".as_bytes();
        assert!(probe_bytes(junk).is_err());
        let junk2 = "-----BEGIN AGE ENCRYPTED FILE-----\nab!d\n".as_bytes();
        assert!(probe_bytes(junk2).is_err());
    }

    fn b64(s: &str) -> String {
        BASE64_STANDARD_NO_PAD.encode(s.as_bytes())
    }

    #[test]
    fn parses_release_stanza() {
        let svc = b64("https://r.example/api");
        let h = format!("age-encryption.org/v1\n-> sealdrop-release rid-1 {svc} bm9uY2U dG9rZW4\nAAAA\n--- bWFj\n");
        let p = probe_bytes(h.as_bytes()).unwrap();
        assert_eq!(p.tags, vec!["sealdrop-release"]);
        let r = p.release.unwrap();
        assert_eq!(r.release_id, "rid-1");
        assert_eq!(r.service, "https://r.example/api");
        assert_eq!(r.nonce_b64, "bm9uY2U");
        assert_eq!(r.unlock_token_b64, "dG9rZW4");
        assert!(!p.needs_passphrase);
    }

    #[test]
    fn release_stanza_with_wrong_arity_is_ignored_but_listed() {
        let svc = b64("https://r.example");
        let h = format!(
            "age-encryption.org/v1\n-> sealdrop-release rid-1 {svc} bm9uY2U\nAAAA\n--- bWFj\n"
        );
        let p = probe_bytes(h.as_bytes()).unwrap();
        assert_eq!(p.tags, vec!["sealdrop-release"]);
        assert!(p.release.is_none());
    }

    #[test]
    fn release_stanza_with_bad_service_base64_is_an_error() {
        let h = "age-encryption.org/v1\n-> sealdrop-release rid-1 !!notb64!! bm9uY2U dG9rZW4\nAAAA\n--- bWFj\n";
        assert!(probe_bytes(h.as_bytes()).is_err());
    }

    #[test]
    fn first_header_line_must_match_exactly() {
        let h = "age-encryption.org/v1x\n-> X25519 abc\nAAAA\n--- bWFj\n";
        assert!(probe_bytes(h.as_bytes()).is_err());
    }
}
