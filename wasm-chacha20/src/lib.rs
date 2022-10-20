mod utils;

use std::str::{self, from_utf8};

use chacha20poly1305::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    ChaCha20Poly1305
};


use wasm_bindgen::prelude::*;

// When the `wee_alloc` feature is enabled, use `wee_alloc` as the global
// allocator.
#[cfg(feature = "wee_alloc")]
#[global_allocator]
static ALLOC: wee_alloc::WeeAlloc = wee_alloc::WeeAlloc::INIT;

#[wasm_bindgen]
extern {
    fn alert(s: &str);
}

const key = ChaCha20Poly1305::generate_key(&mut OsRng);
const cipher = ChaCha20Poly1305::new(&key);
const nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng); // 96-bits;

#[wasm_bindgen]
pub fn encrypt(s: &str) {
    cipher.encrypt(&nonce, s.as_bytes().as_ref()).unwrap();
}

#[wasm_bindgen]
pub fn decrypt(s: &str) {
    from_utf8(&cipher.decrypt(&nonce, s.as_bytes().as_ref()).unwrap()).unwrap();
}
