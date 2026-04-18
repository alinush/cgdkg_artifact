//! Seed derivation helper used to seed a ChaCha20 RNG from arbitrary input.

use sha2::{Digest, Sha256};
use zeroize::Zeroize;

use crate::rng::RAND_ChaCha20;

const SEED_LEN: usize = 32;

#[derive(Clone, Zeroize)]
#[zeroize(drop)]
pub struct Seed {
    value: [u8; SEED_LEN],
}

impl Seed {
    fn new(input: &[u8], domain_separator: &str) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(domain_separator.as_bytes());
        hasher.update(input);
        let digest = hasher.finalize();
        let mut value = [0u8; SEED_LEN];
        value.copy_from_slice(&digest);
        Self { value }
    }

    pub fn from_bytes(value: &[u8]) -> Self {
        Self::new(value, "crypto-seed-from-bytes")
    }

    pub fn into_rng(self) -> RAND_ChaCha20 {
        RAND_ChaCha20::new(self.value)
    }
}
