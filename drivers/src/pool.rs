//! Reused packet buffers and a fast hasher for routing tables.
//!
//! Every driver allocates and hashes the same way, so these shrink costs shared by all of them.

use std::cell::RefCell;
use std::hash::{BuildHasherDefault, Hasher};

/// Buffers kept per thread for reuse.
const MAX_FREE: usize = 4096;
/// Large enough for any packet in the benchmarks, so recycled buffers never need to grow.
const CAPACITY: usize = 2048;

thread_local! {
    static FREE: RefCell<Vec<Vec<u8>>> = const { RefCell::new(Vec::new()) };
}

/// Returns a buffer of `len` bytes, reusing a recycled one if possible.
///
/// A recycled buffer keeps its old contents. Callers overwrite all of it: encryption writes
/// every byte of its output, and decryption copies the message in first.
pub fn take(len: usize) -> Vec<u8> {
    let mut buffer = FREE
        .with_borrow_mut(Vec::pop)
        .unwrap_or_else(|| Vec::with_capacity(CAPACITY.max(len)));
    if buffer.len() < len {
        buffer.resize(len, 0);
    } else {
        buffer.truncate(len);
    }

    buffer
}

/// Returns a buffer for reuse.
pub fn recycle(buffer: Vec<u8>) {
    if buffer.capacity() >= CAPACITY {
        FREE.with_borrow_mut(|free| {
            if free.len() < MAX_FREE {
                free.push(buffer);
            }
        });
    }
}

/// FxHash's multiply-and-rotate, which suits keys that are already random, like tunnel IDs.
#[derive(Default)]
pub(crate) struct FastHasher(u64);

impl Hasher for FastHasher {
    fn write(&mut self, bytes: &[u8]) {
        for chunk in bytes.chunks(8) {
            let mut word = [0; 8];
            word[..chunk.len()].copy_from_slice(chunk);
            self.write_u64(u64::from_le_bytes(word));
        }
    }

    fn write_u64(&mut self, word: u64) {
        self.0 = (self.0.rotate_left(5) ^ word).wrapping_mul(0x51_7c_c1_b7_27_22_0a_95);
    }

    fn write_u32(&mut self, word: u32) {
        self.write_u64(u64::from(word));
    }

    fn write_u16(&mut self, word: u16) {
        self.write_u64(u64::from(word));
    }

    fn write_u8(&mut self, word: u8) {
        self.write_u64(u64::from(word));
    }

    fn write_usize(&mut self, word: usize) {
        self.write_u64(word as u64);
    }

    fn finish(&self) -> u64 {
        self.0
    }
}

pub(crate) type FastMap<K, V> = std::collections::HashMap<K, V, BuildHasherDefault<FastHasher>>;
