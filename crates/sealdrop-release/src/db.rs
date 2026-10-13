use std::sync::Mutex;

use rusqlite::{params, Connection, OptionalExtension};

pub struct Db(Mutex<Connection>);

#[derive(Debug, Clone)]
pub struct ReleaseRow {
    pub release_id: String,
    pub k_release: Option<String>,
    pub window_secs: i64,
    pub unlock_token_hash: String,
    pub package_sha256: String,
    pub created: String,
    pub first_unlock: Option<String>,
    pub expires_at: Option<String>,
    pub expires_unix: Option<i64>,
    pub unlock_count: i64,
}

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS releases (
  release_id TEXT PRIMARY KEY, k_release TEXT, window_secs INTEGER NOT NULL,
  unlock_token_hash TEXT NOT NULL, package_sha256 TEXT NOT NULL, created TEXT NOT NULL,
  first_unlock TEXT, expires_at TEXT, expires_unix INTEGER, unlock_count INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS tokens (name TEXT PRIMARY KEY, hash TEXT NOT NULL, created TEXT NOT NULL);
";

impl Db {
    pub fn open(path: &str) -> anyhow::Result<Self> {
        Self::init(Connection::open(path)?)
    }

    pub fn open_memory() -> anyhow::Result<Self> {
        Self::init(Connection::open_in_memory()?)
    }

    fn init(c: Connection) -> anyhow::Result<Self> {
        c.execute_batch(SCHEMA)?;
        Ok(Self(Mutex::new(c)))
    }

    /// Creates a deposit token, stores only its hash, returns the plaintext once.
    pub fn create_token(&self, name: &str) -> anyhow::Result<String> {
        let mut raw = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::rng(), &mut raw);
        let token = base64::Engine::encode(&base64::prelude::BASE64_URL_SAFE_NO_PAD, raw);
        let hash = sealdrop_core::hashing::sha256_hex(token.as_bytes());
        self.0.lock().unwrap().execute(
            "INSERT OR REPLACE INTO tokens(name, hash, created) VALUES (?1, ?2, ?3)",
            params![name, hash, chrono::Utc::now().to_rfc3339()],
        )?;
        Ok(token)
    }

    pub fn token_valid(&self, token: &str) -> anyhow::Result<bool> {
        let hash = sealdrop_core::hashing::sha256_hex(token.as_bytes());
        let n: i64 = self.0.lock().unwrap().query_row(
            "SELECT COUNT(*) FROM tokens WHERE hash = ?1",
            params![hash],
            |r| r.get(0),
        )?;
        Ok(n > 0)
    }

    /// Returns `false` (and changes nothing) when the id is already taken.
    pub fn insert_release(
        &self,
        id: &str,
        k: &str,
        window: i64,
        token_hash: &str,
        pkg: &str,
        now: &str,
    ) -> anyhow::Result<bool> {
        let n = self.0.lock().unwrap().execute(
            "INSERT OR IGNORE INTO releases(release_id, k_release, window_secs, unlock_token_hash, package_sha256, created) VALUES (?1,?2,?3,?4,?5,?6)",
            params![id, k, window, token_hash, pkg, now],
        )?;
        Ok(n == 1)
    }

    pub fn get_release(&self, id: &str) -> anyhow::Result<Option<ReleaseRow>> {
        Ok(self
            .0
            .lock()
            .unwrap()
            .query_row(
                "SELECT release_id, k_release, window_secs, unlock_token_hash, package_sha256, created, first_unlock, expires_at, expires_unix, unlock_count FROM releases WHERE release_id = ?1",
                params![id],
                |r| {
                    Ok(ReleaseRow {
                        release_id: r.get(0)?,
                        k_release: r.get(1)?,
                        window_secs: r.get(2)?,
                        unlock_token_hash: r.get(3)?,
                        package_sha256: r.get(4)?,
                        created: r.get(5)?,
                        first_unlock: r.get(6)?,
                        expires_at: r.get(7)?,
                        expires_unix: r.get(8)?,
                        unlock_count: r.get(9)?,
                    })
                },
            )
            .optional()?)
    }

    /// Records the first unlock; a no-op if one is already recorded.
    pub fn mark_first_unlock(
        &self,
        id: &str,
        first: &str,
        expires_at: &str,
        expires_unix: i64,
    ) -> anyhow::Result<()> {
        self.0.lock().unwrap().execute(
            "UPDATE releases SET first_unlock = ?2, expires_at = ?3, expires_unix = ?4 WHERE release_id = ?1 AND first_unlock IS NULL",
            params![id, first, expires_at, expires_unix],
        )?;
        Ok(())
    }

    pub fn bump_unlock_count(&self, id: &str) -> anyhow::Result<()> {
        self.0.lock().unwrap().execute(
            "UPDATE releases SET unlock_count = unlock_count + 1 WHERE release_id = ?1",
            params![id],
        )?;
        Ok(())
    }

    pub fn delete_key(&self, id: &str) -> anyhow::Result<()> {
        self.0.lock().unwrap().execute(
            "UPDATE releases SET k_release = NULL WHERE release_id = ?1",
            params![id],
        )?;
        Ok(())
    }

    /// Deletes keys for every release whose window has passed (rows are kept for receipts
    /// and purged after 90 days). Returns the number of keys deleted.
    pub fn sweep_expired(&self, now_unix: i64) -> anyhow::Result<usize> {
        self.sweep_expired_unix(now_unix, 90)
    }

    pub fn sweep_expired_unix(&self, now_unix: i64, retention_days: i64) -> anyhow::Result<usize> {
        let c = self.0.lock().unwrap();
        let n = c.execute(
            "UPDATE releases SET k_release = NULL WHERE k_release IS NOT NULL AND expires_unix IS NOT NULL AND expires_unix <= ?1",
            params![now_unix],
        )?;
        c.execute(
            "DELETE FROM releases WHERE expires_unix IS NOT NULL AND expires_unix <= ?1",
            params![now_unix - retention_days * 86_400],
        )?;
        Ok(n)
    }
}
