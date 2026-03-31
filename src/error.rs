//! Error type

use rand::rngs;
use std::io;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("Input/Output error")]
    IO(#[from] io::Error),
    #[error("Random Number Generator error")]
    RNG(#[from] rngs::SysError),
    #[error("Key Derivation Function error")]
    KDF(#[from] argon2::Error),
    #[error("Cipher error")]
    Cipher(#[from] aes_gcm::Error),
}
