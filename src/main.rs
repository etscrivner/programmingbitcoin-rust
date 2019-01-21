pub mod programmingbitcoin;

extern crate hmac;
extern crate rug;
extern crate sha2;

use rug::Integer;
use rug::integer::Order;
use std::rc::Rc;

use programmingbitcoin::ecdsa::*;
use programmingbitcoin::serialization::*;

fn main() {
    let curve = Rc::new(CryptographicCurve::new_secp256k1());
    let private_key = PrivateKey::new(curve.make_element(Integer::from(5000)), &curve);
    let encoded = private_key.public_key.as_sec();
    println!("{:02x?} - {}", encoded, encoded.len());

    let x = Integer::from(0x001234);
    let result = x.to_digits::<u8>(Order::MsfBe);
    println!("{:x?}", result);
}
