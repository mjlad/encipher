use rand::SeedableRng;
use rand::rngs::ChaCha20Rng;
use rand::seq::SliceRandom;



/// A substitution cipher lookup table for a single encryption layer.
///
/// Contains two precomputed tables:
/// - `enc`: maps plaintext bytes to ciphertext bytes.
/// - `dec`: maps ciphertext bytes back to plaintext bytes.
#[derive(Debug)]
pub struct CipherList {
    pub enc: [u8; 256],
    pub dec: [u8; 256],
}

impl CipherList {
    /// Builds an encrypt/decrypt lookup table using a seeded RNG and a step offset.
    ///
    /// `enc` and `dec` are precomputed substitution tables to guarantee
    /// O(1) encryption and decryption per byte at runtime.
    pub fn new(rng: &mut ChaCha20Rng, step: u8) -> Self {
        let mut forward: [u8; 256] = core::array::from_fn(|i| i as u8);
        forward.shuffle(rng);

        let step = step as usize;
        let mut reverse = [0u8; 256];

        for (i, &v) in forward.iter().enumerate() {
            reverse[v as usize] = i as u8;
        }

        let enc = core::array::from_fn(|i| {
            forward[(reverse[i] as usize + step) % 256]
        });

        let dec = core::array::from_fn(|i| {
            forward[(256 + reverse[i] as usize - step) % 256]
        });

        
        #[cfg(debug_assertions)]
        for byte in 0u8..=255 {
            debug_assert_eq!(
                dec[enc[byte as usize] as usize],
                byte,
                "List error when byte={}", byte
            );
        }

        CipherList { enc, dec }
    }
}



/// Generates 100 substitution lists from a fixed key.
/// Count is fixed in the type signature for performance
/// and to avoid unnecessary heap allocation.
pub fn generate_lists(key: u64, step: u8) -> Box<[CipherList; 100]> {
    let mut rng = ChaCha20Rng::seed_from_u64(key);
    let lists: Vec<CipherList> = (0..100).map(|_| CipherList::new(&mut rng, step)).collect();
    lists.try_into().unwrap()
}
