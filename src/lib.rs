#![deny(missing_docs)]
//! This module could be used to encrypt/decrypt tokens

use rand::RngCore;
use ring::aead;
use ring::digest;
use std::error;
use std::fmt;

const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;

/// Real derived key
#[derive(Clone, PartialEq)]
pub struct Ec3Key(pub [u8; 32]);

impl Ec3Key {
    /// Create a new key that could be used for encryption/decryption afterwards
    pub fn new(key: &str) -> Self {
        Self::new_raw(key.as_bytes())
    }

    /// Create a new key from raw string
    pub fn new_raw(key: &[u8]) -> Self {
        let mut digest = [0u8; digest::SHA256_OUTPUT_LEN];
        digest.clone_from_slice(&digest::digest(&digest::SHA256, key).as_ref());
        Self(digest)
    }

    /// Encrypts token with key
    pub fn encrypt(&self, token: &str) -> String {
        let mut nonce = [0u8; aead::NONCE_LEN];
        let mut generator = rand::thread_rng();

        generator.fill_bytes(&mut nonce);

        let key = aead::UnboundKey::new(&aead::AES_256_GCM, &self.0)
            .expect("Key has fixed length, could not fail");

        let mut in_out = token.as_bytes().to_vec();

        let less_safe_key = aead::LessSafeKey::new(key);
        let tag = less_safe_key
            .seal_in_place_separate_tag(
                aead::Nonce::assume_unique_for_key(nonce),
                aead::Aad::from(&[]),
                &mut in_out,
            )
            .expect("should not fail");

        let mut encrypted = Vec::with_capacity(NONCE_LEN + token.len() + TAG_LEN);

        encrypted.extend_from_slice(nonce.as_ref());
        encrypted.extend_from_slice(&in_out);
        encrypted.extend_from_slice(tag.as_ref());

        base64::encode_config(&encrypted, base64::URL_SAFE_NO_PAD)
    }

    /// Decrypt given token with already derived key
    pub fn decrypt(&self, token: &str) -> Result<String, DecryptionError> {
        let mut chars = base64::decode_config(token, base64::URL_SAFE_NO_PAD)?;
        let length = chars.len();

        if length < (NONCE_LEN + TAG_LEN) as usize {
            return Err(DecryptionError::IOError("invalid input length"));
        }

        let less_key = aead::LessSafeKey::new(
            aead::UnboundKey::new(&aead::AES_256_GCM, &self.0).expect("should not fail"),
        );
        let mut nonce = [0u8; 12];
        nonce.clone_from_slice(&chars[..NONCE_LEN]);
        let result = less_key.open_in_place(
            aead::Nonce::assume_unique_for_key(nonce),
            aead::Aad::from(&[]),
            &mut chars[NONCE_LEN..],
        );

        if result.is_err() {
            return Err(DecryptionError::IOError("decryption failed"));
        }

        let s = String::from_utf8(
            chars
                .into_iter()
                .skip(NONCE_LEN)
                .take(length - NONCE_LEN - TAG_LEN)
                .collect(),
        )?;

        Ok(s)
    }
}

/// EncryptV3 encrypts the given content using the supplied key.
///
/// ```
/// let input = "ec_expire=1257642471&ec_secure=33";
///
/// let encrypted = ectoken::encrypt_v3("testkey123", input);
/// println!("{}", encrypted);
/// # let decrypted = ectoken::decrypt_v3("testkey123", &encrypted).unwrap();
///
/// # assert_eq!(input, decrypted);
/// ```
pub fn encrypt_v3(key: &str, token: &str) -> String {
    let key = Ec3Key::new(key);

    key.encrypt(token)
}

/// Decrypts the given token using the supplied key. On success,
/// returns the decrypted content. If the token is invalid or
/// can not be decrypted, returns DecryptionError.
///
/// ```
/// let decrypted = ectoken::decrypt_v3("testkey123", "bs4W7wyy0OjyBQMhAaahSVo2sG4gKEzuOegBf9kI-ZzG8Gz4FQuFud2ndvmuXkReeRnKFYXTJ7q5ynniGw").unwrap();
///
/// assert_eq!("ec_expire=1257642471&ec_secure=33", decrypted);
/// ```
pub fn decrypt_v3(key: &str, token: &str) -> Result<String, DecryptionError> {
    let key = Ec3Key::new(key);

    key.decrypt(token)
}

/// Errors that can occur while decoding.
#[derive(Debug)]
pub enum DecryptionError {
    /// An invalid base64 string was found in the input.
    InvalidBase64(base64::DecodeError),
    /// An invalid UTF8 string was found once decrypted.
    InvalidUTF8(std::string::FromUtf8Error),
    /// An invalid input/output was
    IOError(&'static str),
}

impl fmt::Display for DecryptionError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            DecryptionError::InvalidBase64(_) => write!(f, "Invalid base64."),
            DecryptionError::InvalidUTF8(_) => write!(f, "Invalid UTF8 string decrypted."),
            DecryptionError::IOError(description) => {
                write!(f, "Input/Output error: {}", description)
            }
        }
    }
}

impl error::Error for DecryptionError {
    fn description(&self) -> &str {
        match *self {
            DecryptionError::InvalidBase64(_) => "invalid base64",
            DecryptionError::InvalidUTF8(_) => "invalid UTF8 string decrypted",
            DecryptionError::IOError(_) => "input/output error",
        }
    }

    fn cause(&self) -> Option<&dyn error::Error> {
        match *self {
            DecryptionError::InvalidBase64(ref previous) => Some(previous),
            DecryptionError::InvalidUTF8(ref previous) => Some(previous),
            _ => None,
        }
    }
}

impl From<base64::DecodeError> for DecryptionError {
    fn from(err: base64::DecodeError) -> DecryptionError {
        DecryptionError::InvalidBase64(err)
    }
}

impl From<std::string::FromUtf8Error> for DecryptionError {
    fn from(err: std::string::FromUtf8Error) -> DecryptionError {
        DecryptionError::InvalidUTF8(err)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_returns_err_on_invalid_base64_string() {
        let decrypted = decrypt_v3(
            "testkey123",
            "af0c6acf7906cd500aee63a4dd2e97ddcb0142601cf83aa9d622289718c4c85413",
        );

        assert!(
            decrypted.is_err(),
            "decryption should be an Error with invalid base64 encoded string"
        );
    }

    #[test]
    fn it_returns_err_on_invalid_length() {
        let decrypted = decrypt_v3("testkey123", "bs4W7wyy");

        assert!(
            decrypted.is_err(),
            "decryption should be an Error with invalid length encoded string"
        );
    }
}
