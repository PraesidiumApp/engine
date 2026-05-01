//! The backbone of Praesidium

use rusqlite::{Connection, OpenFlags};
use serde::Serialize;
use std::path::Path;
use zeroize::Zeroizing;

use crate::{
    crypto::{
        constants::{AUTH_TAG_SIZE, MASTER_KEY_SIZE, NONCE_SIZE, SALT_SIZE},
        master_key::derive,
        payload::{decrypt, encrypt},
        utils::fill_with_random_bytes,
    },
    error::Error,
};

pub mod crypto;
pub mod error;

const VAULT_VERSION: i64 = 1;
const CANARY_LABEL: &str = "praesidium_canary";
const CANARY_KIND: &str = "canary";
const CANARY_PAYLOAD: &str = "this is a canary";

mod sql {
    pub(super) const CHECK_TABLE_COUNT: &str = "
        SELECT count(*) FROM sqlite_master WHERE type='table'
    ";
    pub(super) const CREATE_SCHEMA: &str = "
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
    pub(super) const INIT_METADATA: &str = "
        INSERT INTO metadata (id, salt, version) VALUES (0, ?1, ?2)
    ";
    pub(super) const CHECK_ITEM_EXISTS: &str = "
        SELECT EXISTS(SELECT 1 FROM items WHERE id = ?1)
    ";
    pub(super) const SAVE_ITEM: &str = "
        INSERT OR REPLACE INTO items (id, label, kind, nonce, auth_tag, payload) 
        VALUES (?1, ?2, ?3, ?4, ?5, ?6);
    ";
    pub(super) const READ_ITEM: &str = "
        SELECT label, kind, nonce, auth_tag, payload FROM items WHERE id = ?1
    ";
    pub(super) const SCAN_ITEMS: &str = "
        SELECT id FROM items WHERE id != 0 ORDER BY label ASC
    ";
}

pub struct Session {
    pub connection: Connection,
    pub master_key: Zeroizing<[u8; MASTER_KEY_SIZE]>,
    pub metadata: SessionMetadata,
    pub items: Vec<SessionItem>,
}

pub struct SessionMetadata {
    pub salt: [u8; SALT_SIZE],
    pub created_at: String,
    pub version: i64,
}

#[derive(Serialize, Clone)]
pub struct SessionItem {
    pub id: i64,
    pub label: String,
    pub kind: String,
    pub payload: Zeroizing<Vec<u8>>,
}

impl Session {
    /// Create a new [Session], creating a new underlying vault
    /// # Arguments
    /// * `path` - Any type that can be converted to a [Path] by the [AsRef] trait
    /// * `password` - A text master password used to protect items inside the new vault
    pub fn new<P: AsRef<Path>>(path: P, password: &mut str) -> Result<Self, Error> {
        let connection = Connection::open(path)?;

        // If file exists (it is not supposed to) and its not a SQLite database it should error (rusqlite)
        // If it IS a SQLite database check its empty before initializing it
        // It would be better to have an atomic operation in rusqlite to guarantee the opened
        // file is new and avoid TOCTOU race conditions but AFAIK there is no such option
        let table_count: i64 =
            connection.query_row(sql::CHECK_TABLE_COUNT, (), |row| row.get(0))?;

        if table_count != 0 {
            // If it's not 0, it's not a new database
            return Err(Error::VaultNotEmpty);
        }

        let mut salt = [0u8; SALT_SIZE];
        fill_with_random_bytes(&mut salt)?;

        let mut master_key = Zeroizing::new([0u8; MASTER_KEY_SIZE]);
        derive(password, &salt, &mut master_key)?;

        connection.execute_batch(sql::CREATE_SCHEMA)?;

        connection.execute(sql::INIT_METADATA, (salt.as_slice(), VAULT_VERSION))?;

        let metadata = SessionMetadata::get(&connection)?;

        // Insert canary item
        let canary = SessionItem::save(
            &connection,
            &master_key,
            0,
            CANARY_LABEL,
            CANARY_KIND,
            &mut CANARY_PAYLOAD.as_bytes().to_vec(),
        )?;

        let items = vec![canary];

        Ok(Self {
            connection,
            master_key,
            metadata,
            items,
        })
    }

    /// Create a new [Session], opening an existing underlying vault
    /// # Arguments
    /// * `path` - Any type that can be converted to a [Path] by the [AsRef] trait
    /// * `password` - A text master password used to unlock items inside the vault
    pub fn open<P: AsRef<Path>>(path: P, password: &mut str) -> Result<Self, Error> {
        let mut connection_flags = OpenFlags::default();
        connection_flags.remove(OpenFlags::SQLITE_OPEN_CREATE);
        let connection = Connection::open_with_flags(path, connection_flags)?;

        let metadata = SessionMetadata::get(&connection)?;

        if metadata.version > VAULT_VERSION {
            return Err(Error::VaultVersionNewer);
        }

        let mut master_key = Zeroizing::new([0u8; MASTER_KEY_SIZE]);
        derive(password, &metadata.salt, &mut master_key)?;

        // Verify canary
        let canary = SessionItem::read(&connection, &master_key, 0)?;

        let mut items = vec![canary];

        SessionItem::scan_and_fill(&connection, &master_key, &mut items)?;

        Ok(Self {
            connection,
            master_key,
            metadata,
            items,
        })
    }
}

impl SessionMetadata {
    fn get(connection: &Connection) -> Result<Self, Error> {
        Ok(connection.query_row(
            "SELECT salt, created_at, version FROM metadata WHERE id = 0",
            [],
            |row| {
                Ok(SessionMetadata {
                    salt: row.get(0)?,
                    created_at: row.get(1)?,
                    version: row.get(2)?,
                })
            },
        )?)
    }
}

impl SessionItem {
    pub fn save(
        connection: &Connection,
        master_key: &[u8; MASTER_KEY_SIZE],
        id: i64,
        label: &str,
        kind: &str,
        payload: &mut [u8],
    ) -> Result<Self, Error> {
        if Self::exists(connection, id)? {
            return Err(Error::ItemExists);
        }

        let mut ad = Vec::new();
        Self::construct_ad(id, label, kind, &mut ad);
        let mut nonce = [0u8; NONCE_SIZE];
        let mut auth_tag = [0u8; AUTH_TAG_SIZE];
        let cleartext_payload = payload.to_vec();

        encrypt(
            master_key,
            Some(ad.as_slice()),
            &mut nonce,
            &mut auth_tag,
            payload,
        )?;

        connection.execute(
            sql::SAVE_ITEM,
            (id, label, kind, nonce, auth_tag, &*payload),
        )?;

        Ok(Self {
            id,
            label: label.to_string(),
            kind: kind.to_string(),
            payload: Zeroizing::new(cleartext_payload),
        })
    }

    pub fn scan_and_fill(
        connection: &Connection,
        master_key: &[u8; MASTER_KEY_SIZE],
        items: &mut Vec<SessionItem>,
    ) -> Result<(), Error> {
        let mut statement = connection.prepare(sql::SCAN_ITEMS)?;

        let ids = statement.query_map((), |row| row.get::<_, i64>(0))?;

        for id_result in ids {
            let id = id_result?;
            let item = Self::read(&connection, master_key, id)?;
            items.push(item);
        }

        Ok(())
    }

    pub fn exists(connection: &Connection, id: i64) -> Result<bool, Error> {
        Ok(connection.query_row(sql::CHECK_ITEM_EXISTS, ((id),), |row| row.get(0))?)
    }

    fn read(
        connection: &Connection,
        master_key: &[u8; MASTER_KEY_SIZE],
        id: i64,
    ) -> Result<Self, Error> {
        let (label, kind, nonce, auth_tag, mut payload): (
            String,
            String,
            [u8; NONCE_SIZE],
            [u8; AUTH_TAG_SIZE],
            Vec<u8>,
        ) = connection.query_row(sql::READ_ITEM, ((id),), |row| {
            Ok((
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                row.get(3)?,
                row.get(4)?,
            ))
        })?;

        let mut ad = Vec::new();
        Self::construct_ad(id, &*label, &*kind, &mut ad);

        decrypt(
            master_key,
            Some(ad.as_slice()),
            &nonce,
            &auth_tag,
            &mut payload,
        )?;

        Ok(Self {
            id,
            label,
            kind,
            payload: Zeroizing::new(payload),
        })
    }

    fn construct_ad(id: i64, label: &str, kind: &str, buffer: &mut Vec<u8>) {
        buffer.extend_from_slice(&id.to_be_bytes());
        buffer.push(b'|');
        buffer.extend_from_slice(label.as_bytes());
        buffer.push(b'|');
        buffer.extend_from_slice(kind.as_bytes());
    }

}
