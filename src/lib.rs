//! The backbone of Praesidium

pub mod crypto;
pub mod error;

use crate::{
    crypto::{MASTER_KEY_SIZE, SALT_SIZE, derive_master_key, fill_with_random_bytes},
    error::Error,
};
use rusqlite::{Connection, OpenFlags};
use std::path::Path;
use zeroize::Zeroizing;

pub const VAULT_VERSION: u32 = 1;

pub struct Session {
    connection: Connection,
    master_key: Zeroizing<[u8; MASTER_KEY_SIZE]>,
    metadata: SessionMetadata,
}

struct SessionMetadata {
    salt: [u8; SALT_SIZE],
    created_at: String,
    version: u32
}

impl Session {
    /// Create a new [Session], creating a new underlying vault
    /// # Arguments
    /// * `path` - Any type that can be converted to a [Path] by the [AsRef] trait
    /// * `password` - A text master password used to protect items inside the new vault
    /// # Errors
    /// * `Err(Error::DB(...))` - If there was any problem trying to connect or query to the database
    /// * `Err(Error::RNG(...))` - If there was any problem with the random number generator
	/// * `Err(Error::KDF(...))` - If there was any problem with the key derivation function
    /// * `Err(Error::VaultNotEmpty)` - If the provided path IS a SQLite database and is NOT empty
    pub fn new<P: AsRef<Path>>(path: P, password: &mut str) -> Result<Self, Error> {
        let vault_connection = Connection::open(path)?;

        // If file exists (it is not supposed to) and its not a SQLite database it should error (rusqlite)
        // If it IS a SQLite database check its empty before initializing it
        // It would be better to have an atomic operation in rusqlite to guarantee the opened
        // file is new and avoid TOCTOU race conditions but AFAIK there is no such option
        let table_count: i64 = vault_connection.query_row(
            "SELECT count(*) FROM sqlite_master WHERE type='table'",
            [],
            |row| row.get(0),
        )?;

        if table_count != 0 {
            // If it's not 0, it's not a new database
            return Err(Error::VaultNotEmpty);
        }

        let mut salt_buffer = [0u8; SALT_SIZE];
        fill_with_random_bytes(&mut salt_buffer)?;

        let mut master_key_buffer = [0u8; MASTER_KEY_SIZE];
        derive_master_key(password, &salt_buffer, &mut master_key_buffer)?;

        // Prepare database schema
        vault_connection.execute_batch(
            "
			-- Vault metadata (Only 1 row ever)
			CREATE TABLE metadata (
				id INTEGER PRIMARY KEY CHECK (id = 1), 
				salt BLOB NOT NULL,
				created_at DATETIME DEFAULT CURRENT_TIMESTAMP NOT NULL,
				version INTEGER NOT NULL
			);

			-- Vault items
			CREATE TABLE items (
				id INTEGER PRIMARY KEY,
				label TEXT NOT NULL,
                type TEXT NOT NULL,
				nonce BLOB NOT NULL,
				auth_tag BLOB NOT NULL,
				ciphertext BLOB NOT NULL
			);
		    ",
        )?;

        // Insert initial metadata, created_at is inserted by SQLite
        vault_connection.execute(
            "INSERT INTO metadata (id, salt, version) VALUES (1, ?1, ?2)",
            (salt_buffer.as_slice(), VAULT_VERSION),
        )?;

        let vault_metadata = SessionMetadata::get(&vault_connection)?;

        Ok(Self {
            connection: vault_connection,
            master_key: Zeroizing::new(master_key_buffer),
            metadata: vault_metadata
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
        let mut vault_connection_flags = OpenFlags::default();
        vault_connection_flags.remove(OpenFlags::SQLITE_OPEN_CREATE);

        let vault_connection = Connection::open_with_flags(path, vault_connection_flags)?;

        let vault_metadata = SessionMetadata::get(&vault_connection)?;

        if vault_metadata.version > VAULT_VERSION {
            return Err(Error::VaultVersionNewer)
        }

        let mut master_key_buffer = [0u8; MASTER_KEY_SIZE];
        derive_master_key(password, &vault_metadata.salt, &mut master_key_buffer)?;

        Ok(
            Self {
                connection: vault_connection,
                master_key: Zeroizing::new(master_key_buffer),
                metadata: vault_metadata
            }
        )
    }
}

impl SessionMetadata {
    fn get(connection: &Connection) -> Result<Self, Error> {
        Ok(
            connection.query_row(
                "SELECT salt, created_at, version FROM metadata WHERE id = 1",
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
