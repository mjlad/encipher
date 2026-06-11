use crate::lists::CipherList;


/// Encrypts raw bytes by rotating through the substitution lists.
/// (start_from + 1) % num_lists ensures the index is always in bounds.
pub fn encrypt_raw(raw_bytes : &[u8], lists: &[CipherList], start_from: usize) -> Vec<u8> {

    let num_lists   = lists.len();
    let mut result  = vec![0u8; raw_bytes.len()];
    let mut current = start_from;

    for (i, &byte) in raw_bytes.iter().enumerate() {
        result[i] = lists[current].enc[byte as usize];
        current = (current + 1) % num_lists;
    }
    result
}


/// Decrypts raw bytes by rotating through the substitution lists.
/// (start_from + 1) % num_lists ensures the index is always in bounds.
pub fn decrypt_raw(encrypted : &[u8], lists: &[CipherList], start_from: usize) -> Vec<u8> {

    let num_lists   = lists.len();
    let mut result  = vec![0u8; encrypted.len()];
    let mut current = start_from;

    for (i, &byte) in encrypted.iter().enumerate() {
        result[i] = lists[current].dec[byte as usize];
        current   = (current + 1) % num_lists;
    }

    result
}
