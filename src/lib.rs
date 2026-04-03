//! The backbone of Praesidium

pub mod crypto;
pub mod error;

use crate::{
    crypto::{MASTER_KEY_SIZE, SALT_SIZE, derive_master_key, fill_with_random_bytes},
    error::{Error, VaultError},
};
use rusqlite::Connection;
use std::path::Path;
use zeroize::{Zeroize, Zeroizing};

pub const VAULT_VERSION: isize = 1;

pub struct Session {
    vault: Connection,
    salt: [u8; SALT_SIZE],
    master_key: Zeroizing<[u8; MASTER_KEY_SIZE]>,
}

impl Session {
    /// Create a new [Session], creating a new underlying vault
    /// # Arguments
    /// * `path` - Any type that can be converted to a [Path] by the [AsRef] trait
    /// * `password` - A text master password used to protect items inside the new vault
    /// # Errors
    /// * `Err(Error::DB(...))` - If there was any problem trying to create, connect or query to the database
    /// * `Err(Error::RNG(...))` - If there was any problem with the random number generator
	/// * `Err(Error::KDF(...))` - If there was any problem with the key derivation function
    /// * `Err(Error::Vault(...))` - If the provided path IS a SQLite database and is NOT empty
    pub fn new<P: AsRef<Path>>(path: P, password: &mut str) -> Result<Self, Error> {
        let vault_connection = Connection::open(path)?;

        // If file exists (it is not supposed to) and its not a SQLite database it should error
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
            return Err(Error::Vault(VaultError::VaultNotEmpty));
        }

        let mut salt_buffer = [0u8; SALT_SIZE];
        fill_with_random_bytes(&mut salt_buffer)?;

        let mut master_key_buffer = [0u8; MASTER_KEY_SIZE];
        derive_master_key(password, &salt_buffer, &mut master_key_buffer)?;

        password.zeroize();

        // Prepare database layout
        vault_connection.execute_batch(
            "
			-- Table for global vault settings (Only 1 row ever)
			CREATE TABLE metadata (
				id INTEGER PRIMARY KEY CHECK (id = 1), 
				salt BLOB NOT NULL,
				created_at DATETIME DEFAULT CURRENT_TIMESTAMP NOT NULL,
				version INTEGER NOT NULL
			);

			-- Table for vault items
			CREATE TABLE items (
				id INTEGER PRIMARY KEY,
				label TEXT NOT NULL,
				nonce BLOB NOT NULL,
				auth_tag BLOB NOT NULL,
				ciphertext BLOB NOT NULL
			);
		",
        )?;

        // Insert initial metadata
        vault_connection.execute(
            "INSERT INTO metadata (id, salt, version) VALUES (1, ?1, ?2)",
            (salt_buffer.as_slice(), VAULT_VERSION),
        )?;

        Ok(Self {
            vault: vault_connection,
            salt: salt_buffer,
            master_key: Zeroizing::new(master_key_buffer),
        })
    }
}
