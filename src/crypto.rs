//! Vault encryption

use crate::error::Error;
use aes_gcm::{AeadInPlace, Aes256Gcm, KeyInit};
use rand::{TryRng, rngs::SysRng};

const SALT_SIZE: usize = 16;
const MASTER_KEY_SIZE: usize = 32;
const NONCE_SIZE: usize = 12;
const AUTH_TAG_SIZE: usize = 16;

/// Fills the provided `buffer` entirely with random bytes
pub fn fill_with_random_bytes(buffer: &mut [u8]) -> Result<(), Error> {
    Ok(SysRng.try_fill_bytes(buffer)?)
}

/// Derives the master key from the provided `password`
/// # Arguments
/// * `password` - User's plain text password
/// * `new_salt` - Indicates if a new salt should be generated (e.g.: changing the password) (read below)
/// * `salt_buffer` - A 16-byte buffer, if `new_salt` is `true` its contents do not matter and will be overwritten with the new salt, if `false` it should contain the salt to be used, the same salt **should not** be used for two different passwords, i.e.: `new_salt` should be `true` if the password is being changed
/// * `master_key_buffer` - Output buffer where the derived 32-byte master key will be written
/// ## Note
/// Function is atomic, if main operation fails middle buffers remain untouched
/// # Errors
/// * If `new_salt` is `true`:
///     * `Err(Error::RNG(...))` - If there was any problem with the random number generator (unlikely)
/// 	* `Err(Error::KDF(...))` - If there was any problem with the key derivation function (unlikely)
/// * If `new_salt` is `false`:
/// 	* `Err(Error::KDF(...))` - If there was any problem with the key derivation function (unlikely)
pub fn derive_master_key(
    password: &str,
    new_salt: bool,
    salt_buffer: &mut [u8; SALT_SIZE],
    master_key_buffer: &mut [u8; MASTER_KEY_SIZE],
) -> Result<(), Error> {
    let argon2_ctx = argon2::Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        argon2::Params::new(65536, 3, 4, Some(MASTER_KEY_SIZE))?,
    );

    if new_salt {
        let mut temp_salt_buffer = [0u8; SALT_SIZE];
        fill_with_random_bytes(&mut temp_salt_buffer)?;

        argon2_ctx.hash_password_into(password.as_bytes(), &temp_salt_buffer, master_key_buffer)?;

        // Update user's salt buffer with the new one once argon2 has succeeded
        salt_buffer.copy_from_slice(&temp_salt_buffer);
    } else {
        argon2_ctx.hash_password_into(password.as_bytes(), salt_buffer, master_key_buffer)?;
    }

    Ok(())
}

/// Encrypts any payload
/// # Arguments
/// * `master_key` - Buffer containing the 32-byte master key (with [derive_master_key])
/// * `associated_data` - Data chained to the given payload, not encrypted but included in the auth tag
/// * `nonce_buffer` - 12-byte buffer where the generated nonce will be written
/// * `auth_tag_buffer` - 16-byte buffer where the authentication tag chained to the ciphertext will be written
/// * `cipher_buffer` - Buffer containing the payload to be overwritten by its respective ciphertext
/// ## Note
/// Function is atomic, if main operation fails middle buffers remain untouched
/// # Errors
/// * `Err(Error::RNG(...))` - If there was any problem with the random number generator
/// * `Err(Error::Cipher(...))` - If there was any problem with the cipher algorithm
pub fn encrypt_payload(
    master_key: &[u8; MASTER_KEY_SIZE],
    associated_data: Option<&[u8]>,
    nonce_buffer: &mut [u8; NONCE_SIZE],
    auth_tag_buffer: &mut [u8; AUTH_TAG_SIZE],
    cipher_buffer: &mut [u8],
) -> Result<(), Error> {
    let aes256gcm_ctx = Aes256Gcm::new(master_key.into());

    let mut nonce = [0u8; NONCE_SIZE];
    fill_with_random_bytes(&mut nonce)?;

    // If associated_data is none an empty slice will be passed (i.e.: no associated data)
    let ad = associated_data.unwrap_or_default();

    let auth_tag = aes256gcm_ctx
        .encrypt_in_place_detached(&nonce.into(), ad, cipher_buffer)?;

    // Write nonce and auth tag buffers once encryption has succeeded
    nonce_buffer.copy_from_slice(&nonce);
    auth_tag_buffer.copy_from_slice(&auth_tag);

    Ok(())
}
