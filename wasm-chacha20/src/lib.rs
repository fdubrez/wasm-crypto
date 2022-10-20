mod utils;

extern crate base64;
extern crate hex;
extern crate crypto;

use crypto::{symmetriccipher::{ SynchronousStreamCipher}};

//use rustc_serialize::hex::FromHex;

use core::str;
use std::iter::repeat;

use wasm_bindgen::prelude::*;

// When the `wee_alloc` feature is enabled, use `wee_alloc` as the global
// allocator.
#[cfg(feature = "wee_alloc")]
#[global_allocator]
static ALLOC: wee_alloc::WeeAlloc = wee_alloc::WeeAlloc::INIT;

fn hex_to_bytes(s: &str) -> Vec<u8> {
    s.from_hex().unwrap()
}

#[wasm_bindgen]
extern {
    fn alert(s: &str);
}

const mykey: &str="0000000000000000000000000000000000000000000000000000000000000000";
const myiv: &str="000000000000000000000000";

const key: Vec<u8>=&hex_to_bytes( mykey)[..];
const iv: Vec<u8>=&hex_to_bytes( myiv)[..];

#[wasm_bindgen]
pub fn encrypt(s: &str) -> str {
    let plain = s.as_bytes();
    // Encrypting
    let mut c = crypto::chacha20::ChaCha20::new(&key, iv);
    let mut output: Vec = repeat(0).take(plain.len()).collect();
    c.process(&plain[..], &mut output[..]);
    hex::encode(output.clone());
}

#[wasm_bindgen]
pub fn decrypt(encrypted: &str) -> str {
    // Decrypting
    let mut c = crypto::chacha20::ChaCha20::new(&key, iv);
    let mut decrypted: Vec = repeat(0).take(encrypted.len()).collect();
    c.process(&mut encrypted[..], &mut decrypted[..]);
    str::from_utf8(&decrypted[..]).unwrap();
}
