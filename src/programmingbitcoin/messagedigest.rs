//! Message digest helpers
use hmac::{Hmac, Mac};
use rug::Integer;
use rug::integer::Order;
use sha2::{Digest, Sha256};

/// Shorthand for HMAC_SHA256 algorithm
type HmacSha256 = Hmac<Sha256>;

/// Returns the SHA-256 hash of the given data
pub fn sha256(data: &[u8]) -> Vec<u8> {
    Sha256::digest(data).to_vec()
}

/// Implements the Hash256 algorithm.
///
/// Hash256(x) = SHA256(SHA256(x)) - two rounds of SHA-256 on data.
pub fn hash256(data: &[u8]) -> Vec<u8> {
    sha256(sha256(data).as_slice())
}

/// Hash256 that outputs an integer value.
pub fn hash256_integer(data: &[u8]) -> Integer {
    // We need an integer with 256-bits (32-bytes) of capacity to match the
    // size of the SHA-256 digest result.
    let mut result = Integer::with_capacity(256);
    result.assign_digits(hash256(data).as_slice(), Order::Msf);
    result
}

/// Computes the HMAC_SHA256(K, M) for the given key and data.
pub fn hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut mac = HmacSha256::new_varkey(key).expect("HMAC can take key of any size");
    mac.input(data);
    mac.result().code().to_vec()
}
