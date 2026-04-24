//! Vault encryption

use crate::error::Error;
use aes_gcm::{AeadInPlace, Aes256Gcm, KeyInit};
use argon2::Argon2;
use rand::{TryRng, rngs::SysRng};
use zeroize::Zeroize;

pub(crate) const SALT_SIZE: usize = 16;
pub(crate) const MASTER_KEY_SIZE: usize = 32;
pub(crate) const NONCE_SIZE: usize = 12;
pub(crate) const AUTH_TAG_SIZE: usize = 16;

/// Fills the provided `buffer` entirely with random bytes
pub fn fill_with_random_bytes(buffer: &mut [u8]) -> Result<(), Error> {
    SysRng.try_fill_bytes(buffer)?;

    Ok(())
}

/// Derives the master key from the provided `password`
/// # Arguments
/// * `password` - User's plain text password, will be wiped after deriving the key for security
/// * `salt_buffer` - A 16-byte buffer containing the salt
/// * `master_key_buffer` - Output buffer where the derived 32-byte master key will be written
/// # Errors
/// * `Err(Error::KDF(...))` - If there was any problem with the key derivation function (unlikely)
/// # Considerations
/// * This function nukes the `password` argument for security if it succeeds
pub fn derive_master_key(
    password: &mut str,
    salt_buffer: &[u8; SALT_SIZE],
    master_key_buffer: &mut [u8; MASTER_KEY_SIZE],
) -> Result<(), Error> {
    let argon2_ctx = Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        argon2::Params::new(262144, 4, 4, Some(MASTER_KEY_SIZE))?,
    );

    argon2_ctx.hash_password_into(password.as_bytes(), salt_buffer, master_key_buffer)?;

    password.zeroize();

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

    let auth_tag = aes256gcm_ctx.encrypt_in_place_detached(&nonce.into(), ad, cipher_buffer)?;

    // Write nonce and auth tag buffers once encryption has succeeded
    nonce_buffer.copy_from_slice(&nonce);
    auth_tag_buffer.copy_from_slice(&auth_tag);

    Ok(())
}

/// Decrypts any payload
/// # Arguments
/// * `master_key` - Buffer containing the 32-byte master key (with [derive_master_key])
/// * `associated_data` - Data chained to the given payload, not decrypted but verified
/// * `nonce_buffer` - 12-byte buffer containing the the nonce used for encryption
/// * `auth_tag_buffer` - 16-byte buffer containing the auth tag produced on encryptio
/// * `cipher_buffer` - Buffer containing the ciphertext to be decrypted into plaintext
/// # Errors
/// * `Err(Error::Cipher(...))` - If there was any problem with the cipher algorithm
pub fn decrypt_payload(
    master_key: &[u8; MASTER_KEY_SIZE],
    associated_data: Option<&[u8]>,
    nonce_buffer: &[u8; NONCE_SIZE],
    auth_tag_buffer: &[u8; AUTH_TAG_SIZE],
    cipher_buffer: &mut [u8],
) -> Result<(), Error> {
    let aes256gcm_ctx = Aes256Gcm::new(master_key.into());

    // If associated_data is none an empty slice will be passed (i.e.: no associated data)
    let ad = associated_data.unwrap_or_default();

    aes256gcm_ctx.decrypt_in_place_detached(
        nonce_buffer.into(),
        ad,
        cipher_buffer,
        auth_tag_buffer.into(),
    )?;

    Ok(())
}
