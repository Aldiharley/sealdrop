//! age's native hybrid post-quantum recipient type `mlkem768x25519` (`age1pq1…`,
//! `AGE-SECRET-KEY-PQ-1…`), per C2SP age.md. The `age` crate 0.12 has no identity for it;
//! this module is replaced by the crate's own types when rage 0.13 ships them.

// The stanza layer that consumes the KEM lands next; drop this allow with it.
#[allow(dead_code)]
pub(crate) mod kem;

pub const TAG: &str = "mlkem768x25519";
pub const INFO: &[u8] = b"age-encryption.org/mlkem768x25519";
pub const LABEL: &str = "postquantum";
pub const RECIPIENT_HRP: &str = "age1pq";
pub const IDENTITY_HRP: &str = "AGE-SECRET-KEY-PQ-";
pub const ENC_LEN: usize = 1120;
pub const PK_LEN: usize = 1216;
pub const BODY_LEN: usize = 32;
