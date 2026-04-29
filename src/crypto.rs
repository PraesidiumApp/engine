//! Vault encryption

pub mod constants {
    pub const SALT_SIZE: usize = 16;
    pub const MASTER_KEY_SIZE: usize = 32;
    pub const NONCE_SIZE: usize = 12;
    pub const AUTH_TAG_SIZE: usize = 16;
}

pub mod utils {
    use crate::error::Error;
    use rand::{TryRng, rngs::SysRng};

    /// Fills the provided `buffer` entirely with random bytes
    pub fn fill_with_random_bytes(buffer: &mut [u8]) -> Result<(), Error> {
        SysRng.try_fill_bytes(buffer)?;

        Ok(())
    }
}

pub mod master_key {
    use argon2::Argon2;
    use zeroize::Zeroize;

    use crate::{
        crypto::constants::{MASTER_KEY_SIZE, SALT_SIZE},
        error::Error,
    };

    /// Derives the master key from the provided `password`
    /// # Arguments
    /// * `password` - User's plain text password, will be wiped after deriving the key for security
    /// * `salt` - A 16-byte buffer containing the salt
    /// * `master_key` - Output buffer where the derived 32-byte master key will be written
    pub fn derive(
        password: &mut str,
        salt: &[u8; SALT_SIZE],
        master_key: &mut [u8; MASTER_KEY_SIZE],
    ) -> Result<(), Error> {
        let argon2_ctx = Argon2::new(
            argon2::Algorithm::Argon2id,
            argon2::Version::V0x13,
            argon2::Params::new(262144, 1, 2, Some(MASTER_KEY_SIZE))?,
        );

        argon2_ctx.hash_password_into(password.as_bytes(), salt, master_key)?;

        password.zeroize();

        Ok(())
    }
}

pub mod payload {
    use aes_gcm::{AeadInPlace, Aes256Gcm, KeyInit};

    use crate::{
        crypto::{
            constants::{AUTH_TAG_SIZE, MASTER_KEY_SIZE, NONCE_SIZE},
            utils::fill_with_random_bytes,
        },
        error::Error,
    };

    /// Encrypts any payload
    /// # Arguments
    /// * `master_key` - Buffer containing the 32-byte master key (with [derive_master_key])
    /// * `associated_data` - Data chained to the given payload, not encrypted but included in the auth tag
    /// * `nonce` - 12-byte buffer where the generated nonce will be written
    /// * `auth_tag` - 16-byte buffer where the authentication tag chained to the ciphertext will be written
    /// * `payload` - Buffer containing the payload to be overwritten by its respective ciphertext
    /// # Note
    /// Function is atomic, if main operation fails middle buffers remain untouched
    pub fn encrypt(
        master_key: &[u8; MASTER_KEY_SIZE],
        associated_data: Option<&[u8]>,
        nonce: &mut [u8; NONCE_SIZE],
        auth_tag: &mut [u8; AUTH_TAG_SIZE],
        payload: &mut [u8],
    ) -> Result<(), Error> {
        let aes_ctx = Aes256Gcm::new(master_key.into());

        let mut nonce_buffer = [0u8; NONCE_SIZE];
        fill_with_random_bytes(&mut nonce_buffer)?;

        // If associated_data is none an empty slice will be passed (i.e.: no associated data)
        let associated_data_buffer = associated_data.unwrap_or_default();

        let auth_tag_buffer = aes_ctx.encrypt_in_place_detached(
            &nonce_buffer.into(),
            associated_data_buffer,
            payload,
        )?;

        // Write nonce and auth tag buffers once encryption has succeeded
        nonce.copy_from_slice(&nonce_buffer);
        auth_tag.copy_from_slice(&auth_tag_buffer);

        Ok(())
    }

    /// Decrypts any payload
    /// # Arguments
    /// * `master_key` - Buffer containing the 32-byte master key (with [derive_master_key])
    /// * `associated_data` - Data chained to the given payload, not decrypted but verified
    /// * `nonce` - 12-byte buffer containing the the nonce used for encryption
    /// * `auth_tag` - 16-byte buffer containing the auth tag produced on encryption
    /// * `payload` - Buffer containing the ciphertext to be decrypted into plaintext
    pub fn decrypt(
        master_key: &[u8; MASTER_KEY_SIZE],
        associated_data: Option<&[u8]>,
        nonce: &[u8; NONCE_SIZE],
        auth_tag: &[u8; AUTH_TAG_SIZE],
        payload: &mut [u8],
    ) -> Result<(), Error> {
        let aes_ctx = Aes256Gcm::new(master_key.into());

        // If associated_data is none an empty slice will be passed (i.e.: no associated data)
        let associated_data_buffer = associated_data.unwrap_or_default();

        aes_ctx.decrypt_in_place_detached(
            nonce.into(),
            associated_data_buffer,
            payload,
            auth_tag.into(),
        )?;

        Ok(())
    }
}
