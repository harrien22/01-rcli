use crate::{process_genpass, TextSignFormat};
use anyhow::{anyhow, Ok, Result};
use chacha20poly1305::{
    aead::{generic_array::typenum::Unsigned, Aead, AeadCore, KeyInit},
    ChaCha20Poly1305, Key, Nonce,
};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use std::{collections::HashMap, io::Read};

pub trait TextSigner {
    // signer could sign any input data
    fn sign(&self, reader: &mut dyn Read) -> Result<Vec<u8>>;
}

pub trait TextVerifier {
    // verifier could verify any input data
    fn verify(&self, reader: &mut dyn Read, sig: &[u8]) -> Result<bool>;
}

pub trait TextEncryptor {
    fn encrypt(&self, reader: &mut dyn Read) -> Result<Vec<u8>>;
}

pub trait TextDecryptor {
    fn decrypt(&self, reader: &mut dyn Read) -> Result<Vec<u8>>;
}

pub struct Blake3 {
    key: [u8; 32],
}

pub struct Ed25519Signer {
    key: SigningKey,
}

pub struct Ed25519Verifier {
    key: VerifyingKey,
}

pub struct Chacha20poly1305 {
    key: [u8; 32],
}

impl TextEncryptor for Chacha20poly1305 {
    fn encrypt(&self, reader: &mut dyn Read) -> Result<Vec<u8>> {
        let mut buf = vec![];
        reader.read_to_end(&mut buf)?;
        let key = Key::from_slice(&self.key);
        let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
        let cipher = ChaCha20Poly1305::new(key);
        let mut ciphertext = cipher
            .encrypt(&nonce, buf.as_ref())
            .map_err(|e| anyhow!(e))?;
        ciphertext.splice(..0, nonce.iter().copied());
        Ok(ciphertext)
    }
}

impl TextDecryptor for Chacha20poly1305 {
    fn decrypt(&self, reader: &mut dyn Read) -> Result<Vec<u8>> {
        type NonceSize = <ChaCha20Poly1305 as AeadCore>::NonceSize;
        let mut buf = vec![];
        reader.read_to_end(&mut buf)?;
        let key = Key::from_slice(&self.key);
        let (nonce, ciphertext) = buf.split_at(NonceSize::to_usize());
        let cipher = ChaCha20Poly1305::new(key);
        let nonce = Nonce::from_slice(nonce);
        let plaintext = cipher.decrypt(nonce, ciphertext).map_err(|e| anyhow!(e))?;
        Ok(plaintext)
    }
}

impl TextSigner for Blake3 {
    fn sign(&self, reader: &mut dyn Read) -> Result<Vec<u8>> {
        let mut buf = vec![];
        reader.read_to_end(&mut buf)?;
        let ret = blake3::keyed_hash(&self.key, &buf);
        Ok(ret.as_bytes().to_vec())
    }
}

impl TextVerifier for Blake3 {
    fn verify(&self, reader: &mut dyn Read, sig: &[u8]) -> Result<bool> {
        let mut buf = vec![];
        reader.read_to_end(&mut buf)?;
        let ret = blake3::keyed_hash(&self.key, &buf);
        Ok(ret.as_bytes() == sig)
    }
}

impl TextSigner for Ed25519Signer {
    fn sign(&self, reader: &mut dyn Read) -> Result<Vec<u8>> {
        let mut buf = vec![];
        reader.read_to_end(&mut buf)?;
        let signature = self.key.sign(&buf);
        Ok(signature.to_bytes().to_vec())
    }
}

impl TextVerifier for Ed25519Verifier {
    fn verify(&self, reader: &mut dyn Read, sig: &[u8]) -> Result<bool> {
        let mut buf = vec![];
        reader.read_to_end(&mut buf)?;
        let sig = (&sig[..64]).try_into()?;
        let signature = Signature::from_bytes(sig);
        Ok(self.key.verify(&buf, &signature).is_ok())
    }
}

impl Blake3 {
    pub fn try_new(key: impl AsRef<[u8]>) -> Result<Self> {
        let key = key.as_ref();
        // convert &[u8] to [u8; 32]
        let key = (&key[..32]).try_into()?;
        Ok(Self::new(key))
    }

    pub fn new(key: [u8; 32]) -> Self {
        Self { key }
    }

    fn generate() -> Result<HashMap<&'static str, Vec<u8>>> {
        let key = process_genpass(32, true, true, true, true)?;
        let mut map = HashMap::new();
        map.insert("blake3.txt", key.as_bytes().to_vec());
        Ok(map)
    }
}

impl Ed25519Signer {
    pub fn try_new(key: impl AsRef<[u8]>) -> Result<Self> {
        let key = key.as_ref();
        // convert &[u8] to [u8; 32]
        let key = (&key[..32]).try_into()?;
        Ok(Self::new(key))
    }

    pub fn new(key: &[u8; 32]) -> Self {
        let key = SigningKey::from_bytes(key);
        Self { key }
    }

    fn generate() -> Result<HashMap<&'static str, Vec<u8>>> {
        let mut csprng = OsRng;
        let sk: SigningKey = SigningKey::generate(&mut csprng);
        let pk: VerifyingKey = (&sk).into();
        let mut map = HashMap::new();
        map.insert("ed25519.sk", sk.to_bytes().to_vec());
        map.insert("ed25519.pk", pk.to_bytes().to_vec());
        Ok(map)
    }
}

impl Ed25519Verifier {
    pub fn try_new(key: impl AsRef<[u8]>) -> Result<Self> {
        let key = key.as_ref();
        // convert &[u8] to [u8; 32]
        let key = (&key[..32]).try_into()?;
        let key = VerifyingKey::from_bytes(key)?;
        Ok(Self { key })
    }
}

impl Chacha20poly1305 {
    pub fn try_new(key: impl AsRef<[u8]>) -> Result<Self> {
        let key = key.as_ref();
        // convert &[u8] to [u8; 32]
        let key = (&key[..32]).try_into()?;
        Ok(Self::new(key))
    }

    pub fn new(key: [u8; 32]) -> Self {
        Self { key }
    }

    // fn generate() -> Result<HashMap<&'static str, Vec<u8>>> {
    //     let key = process_genpass(32, true, true, true, true)?;
    //     let mut map = HashMap::new();
    //     map.insert("chacha20poly1305.txt", key.as_bytes().to_vec());
    //     Ok(map)
    // }
}

pub fn process_text_sign(
    reader: &mut dyn Read,
    key: &[u8],
    format: TextSignFormat,
) -> Result<Vec<u8>> {
    let signer: Box<dyn TextSigner> = match format {
        TextSignFormat::Blake3 => Box::new(Blake3::try_new(key)?),
        TextSignFormat::Ed25519 => Box::new(Ed25519Signer::try_new(key)?),
    };

    signer.sign(reader)
}

pub fn process_text_verify(
    reader: &mut dyn Read,
    key: &[u8],
    sig: &[u8],
    format: TextSignFormat,
) -> Result<bool> {
    let verifier: Box<dyn TextVerifier> = match format {
        TextSignFormat::Blake3 => Box::new(Blake3::try_new(key)?),
        TextSignFormat::Ed25519 => Box::new(Ed25519Verifier::try_new(key)?),
    };
    verifier.verify(reader, sig)
}

pub fn process_text_encrypt(reader: &mut dyn Read, key: &[u8]) -> Result<Vec<u8>> {
    let encryptor = Chacha20poly1305::try_new(key)?;
    encryptor.encrypt(reader)
}

pub fn process_text_decrypt(reader: &mut dyn Read, key: &[u8]) -> Result<Vec<u8>> {
    let decryptor = Chacha20poly1305::try_new(key)?;
    decryptor.decrypt(reader)
}

pub fn process_text_key_generate(format: TextSignFormat) -> Result<HashMap<&'static str, Vec<u8>>> {
    match format {
        TextSignFormat::Blake3 => Blake3::generate(),
        TextSignFormat::Ed25519 => Ed25519Signer::generate(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    use std::io::Cursor;

    const KEY: &[u8] = include_bytes!("../../fixtures/blake3.txt");

    #[test]
    fn test_process_text_sign() -> Result<()> {
        let mut reader = "hello".as_bytes();
        let mut reader1 = "hello".as_bytes();
        let format = TextSignFormat::Blake3;
        let sig = process_text_sign(&mut reader, KEY, format)?;
        let ret = process_text_verify(&mut reader1, KEY, &sig, format)?;
        assert!(ret);
        Ok(())
    }

    #[test]
    fn test_process_text_verify() -> Result<()> {
        let mut reader = "hello".as_bytes();
        let format = TextSignFormat::Blake3;
        let sig = "33Ypo4rveYpWmJKAiGnnse-wHQhMVujjmcVkV4Tl43k";
        let sig = URL_SAFE_NO_PAD.decode(sig)?;
        let ret = process_text_verify(&mut reader, KEY, &sig, format)?;
        assert!(ret);
        Ok(())
    }

    #[test]
    fn test_process_text_chacha20poly1305() -> Result<()> {
        let mut reader = "hello world!".as_bytes();
        let verify_str = "hello world!".as_bytes();
        let encrypted = process_text_encrypt(&mut reader, KEY)?;
        let decrypted = process_text_decrypt(&mut Cursor::new(encrypted), KEY)?;
        let ret = String::from_utf8(decrypted)?;
        assert_eq!(verify_str, ret.as_bytes());
        Ok(())
    }
}
