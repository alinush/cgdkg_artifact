//! Simple ChaCha20-seeded RNG wrapper, implementing `rand_core::RngCore`.

use rand_chacha::{
    rand_core::{RngCore, SeedableRng},
    ChaCha20Rng,
};

#[allow(non_camel_case_types)]
#[derive(Debug)]
pub struct RAND_ChaCha20 {
    inner: ChaCha20Rng,
}

impl RAND_ChaCha20 {
    pub fn new(seed: [u8; 32]) -> Self {
        RAND_ChaCha20 {
            inner: ChaCha20Rng::from_seed(seed),
        }
    }
}

impl RngCore for RAND_ChaCha20 {
    fn next_u32(&mut self) -> u32 {
        self.inner.next_u32()
    }
    fn next_u64(&mut self) -> u64 {
        self.inner.next_u64()
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.inner.fill_bytes(dest);
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.inner.try_fill_bytes(dest)
    }
}
