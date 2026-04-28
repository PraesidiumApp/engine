//! The backbone of Praesidium

pub mod crypto;
pub mod error;

use crate::{
    crypto::{AUTH_TAG_SIZE, MASTER_KEY_SIZE, NONCE_SIZE, SALT_SIZE, decrypt_payload, derive_master_key, encrypt_payload, fill_with_random_bytes},
    error::Error,
};
use rusqlite::{Connection, OpenFlags};
use std::path::Path;
use zeroize::Zeroizing;

pub const VAULT_VERSION: i64 = 1;

const SCHEMA_SQL_BATCH: &str = "
    -- Vault metadata (Only 1 row ever)
    CREATE TABLE metadata (
        id INTEGER PRIMARY KEY CHECK (id = 0), 
        salt BLOB NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP NOT NULL,
        version INTEGER NOT NULL
    );

    -- Vault items
    CREATE TABLE items (
        id INTEGER PRIMARY KEY,
        label TEXT NOT NULL,
        kind TEXT NOT NULL,
        nonce BLOB NOT NULL,
        auth_tag BLOB NOT NULL,
        payload BLOB NOT NULL
    );
";

pub struct Session {
    connection: Connection,
    master_key: Zeroizing<[u8; MASTER_KEY_SIZE]>,
    pub metadata: SessionMetadata,
    pub items: Vec<SessionItem>
}

pub struct SessionMetadata {
    salt: [u8; SALT_SIZE],
    pub created_at: String,
    pub version: i64
}

pub struct SessionItem {
    pub label: String,
    pub kind: String,
    nonce: [u8; NONCE_SIZE],
    auth_tag: [u8; AUTH_TAG_SIZE],
    pub payload: SessionItemPayload
}

enum SessionItemPayload {
    Cleartext(Zeroizing<String>),
    Ciphertext(Vec<u8>)
}

impl Session {
    /// Create a new [Session], creating a new underlying vault
    /// # Arguments
    /// * `path` - Any type that can be converted to a [Path] by the [AsRef] trait
    /// * `password` - A text master password used to protect items inside the new vault
    /// # Errors
    /// * `Err(Error::DB(...))` - If there was any problem trying to connect or query to the database
    /// * `Err(Error::RNG(...))` - If there was any problem with the random number generator
    /// * `Err(Error::Cipher(...))` - If there was any problem with the cipher algorithm
	/// * `Err(Error::KDF(...))` - If there was any problem with the key derivation function
    /// * `Err(Error::VaultNotEmpty)` - If the provided path IS a SQLite database and is NOT empty
    pub fn new<P: AsRef<Path>>(path: P, password: &mut str) -> Result<Self, Error> {
        let connection = Connection::open(path)?;

        // If file exists (it is not supposed to) and its not a SQLite database it should error (rusqlite)
        // If it IS a SQLite database check its empty before initializing it
        // It would be better to have an atomic operation in rusqlite to guarantee the opened
        // file is new and avoid TOCTOU race conditions but AFAIK there is no such option
        let table_count: i64 = connection.query_row(
            "SELECT count(*) FROM sqlite_master WHERE type='table'",
            [],
            |row| row.get(0),
        )?;

        if table_count != 0 {
            // If it's not 0, it's not a new database
            return Err(Error::VaultNotEmpty);
        }

        let mut salt = [0u8; SALT_SIZE];
        fill_with_random_bytes(&mut salt)?;

        let mut master_key = [0u8; MASTER_KEY_SIZE];
        derive_master_key(password, &salt, &mut master_key)?;

        // Prepare database schema
        connection.execute_batch(SCHEMA_SQL_BATCH)?;

        // Insert initial metadata, created_at is inserted by SQLite
        connection.execute(
            "INSERT INTO metadata (id, salt, version) VALUES (0, ?1, ?2)",
            (salt.as_slice(), VAULT_VERSION),
        )?;

        let metadata = SessionMetadata::get(&connection)?;

        // Insert canary item
        let mut ad = Vec::new();
        SessionItem::construct_ad_buffer(0, "praesidium_canary", "canary", &mut ad);
        let mut nonce = [0u8; NONCE_SIZE];
        let mut auth_tag = [0u8; AUTH_TAG_SIZE];
        let mut payload = *b"If you can read this, the master key is correct";

        encrypt_payload(&master_key, Some(ad.as_slice()), &mut nonce, &mut auth_tag, &mut payload)?;

        connection.execute(
            "
                INSERT INTO items (id, label, kind, nonce, auth_tag, payload) 
                VALUES (0, ?1, ?2, ?3, ?4, ?5);
            ",
            ("praesidium_canary", "canary", nonce, auth_tag, payload)
        )?;

        Ok(Self {
            connection: connection,
            master_key: Zeroizing::new(master_key),
            metadata: metadata,
            items: Vec::new()
        })
    }

    /// Create a new [Session], opening an existing underlying vault
    /// # Arguments
    /// * `path` - Any type that can be converted to a [Path] by the [AsRef] trait
    /// * `password` - A text master password used to unlock items inside the vault
    /// # Errors
    /// * `Err(Error::DB(...))` - If there was any problem trying to connect or query to the database
	/// * `Err(Error::KDF(...))` - If there was any problem with the key derivation function
    pub fn open<P: AsRef<Path>>(path: P, password: &mut str) -> Result<Self, Error> {
        let mut connection_flags = OpenFlags::default();
        connection_flags.remove(OpenFlags::SQLITE_OPEN_CREATE);

        let connection = Connection::open_with_flags(path, connection_flags)?;

        let metadata = SessionMetadata::get(&connection)?;

        if metadata.version > VAULT_VERSION {
            return Err(Error::VaultVersionNewer)
        }

        let mut master_key = [0u8; MASTER_KEY_SIZE];
        derive_master_key(password, &metadata.salt, &mut master_key)?;

        // Verify canary
        let ad = connection.query_row(
            "SELECT id, label, kind FROM items WHERE id = 0",
            [],
            |row| {
                let mut ad = Vec::new();
                let id: i64 = row.get(0)?;
                let label: String = row.get(1)?;
                let kind: String = row.get(2)?;
                SessionItem::construct_ad_buffer(id, label.as_str(), kind.as_str(), &mut ad);
                Ok(ad)
            }
        )?;
        let nonce: [u8; NONCE_SIZE] = connection.query_row(
            "SELECT nonce FROM items WHERE id = 0",
            [],
            |row| {
                Ok(row.get(0)?)
            }
        )?;
        let auth_tag: [u8; AUTH_TAG_SIZE] = connection.query_row(
            "SELECT auth_tag FROM items WHERE id = 0",
            [],
            |row| {
                Ok(row.get(0)?)
            }
        )?;
        let mut payload: Vec<u8> = connection.query_row(
            "SELECT payload FROM items WHERE id = 0",
            [],
            |row| {
                Ok(row.get(0)?)
            }
        )?;

        decrypt_payload(&master_key, Some(ad.as_slice()), &nonce, &auth_tag, &mut payload)?;

        Ok(
            Self {
                connection: connection,
                master_key: Zeroizing::new(master_key),
                metadata: metadata,
                items: Vec::new()
            }
        )
    }

}

impl SessionMetadata {
    fn get(connection: &Connection) -> Result<Self, Error> {
        Ok(
            connection.query_row(
                "SELECT salt, created_at, version FROM metadata WHERE id = 0",
                [],
                |row| Ok(SessionMetadata {
                    salt: row.get(0)?,
                    created_at: row.get(1)?,
                    version: row.get(2)?,
                })
            )?
        )
    }
}

impl SessionItem {
    fn construct_ad_buffer(id: i64, label: &str, kind: &str, buffer: &mut Vec<u8>) {
        buffer.extend_from_slice(&id.to_be_bytes());
        buffer.push(b'|');
        buffer.extend_from_slice(label.as_bytes());
        buffer.push(b'|');
        buffer.extend_from_slice(kind.as_bytes());
    }
}
