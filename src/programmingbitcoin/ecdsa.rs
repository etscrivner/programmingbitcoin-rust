//! Elliptic-Curve Digital Signature Algorithm (ECDSA) implementation
use std::iter;
use std::rc::Rc;

use rug::Integer;
use rug::integer::Order;
use rug::ops::*;

use programmingbitcoin::ellipticcurve::*;
use programmingbitcoin::finitefield::*;
use programmingbitcoin::messagedigest::*;

/// Represents a cryptographic elliptic curve over a finite field
pub struct CryptographicCurve {
    pub finite_curve: FiniteEllipticCurve,
    pub generator_point: Point,
    pub order: Rc<GaloisField>
}

impl CryptographicCurve {
    /// Create a new cryptographic curve with the given properties
    pub fn new(curve: FiniteEllipticCurve,
               generator_point: Point,
               order: Integer) -> CryptographicCurve
    {
        CryptographicCurve {
            finite_curve: curve,
            generator_point: generator_point,
            order: Rc::new(GaloisField::new(order))
        }
    }

    /// Create a secp256k1 cryptograhic curve from pre-defined constants
    pub fn new_secp256k1() -> CryptographicCurve
    {
        let gx = Integer::from_str_radix(
            "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798", 16
        ).unwrap();
        let gy = Integer::from_str_radix(
            "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8", 16
        ).unwrap();
        let order = Integer::from_str_radix(
            "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141", 16
        ).unwrap();
        let p = Integer::from(2).pow(256) - Integer::from(2).pow(32) - Integer::from(977);

        let field = Rc::new(GaloisField::new(p));
        let curve = EllipticCurve::new(Integer::from(0), Integer::from(7));
        let secp256k1_curve = FiniteEllipticCurve::new(curve, &field);
        let generator_point = secp256k1_curve.make_point_integral(gx, gy).unwrap();

        CryptographicCurve::new(secp256k1_curve, generator_point, order)
    }

    /// Make element modulo the order of the curve
    pub fn make_element(&self, value: Integer) -> FieldElement {
        // We need to do our scalar arithmetic modulo the curve's order instead
        // of using the prime factor.
        FieldElement::new(value, &self.order.clone())
    }

    /// Make a new point modulo the prime of the curve
    pub fn make_point_integral(&self, x: Integer, y: Integer) -> Result<Point,String> {
        self.finite_curve.make_point_integral(x,y)
    }
}

/// An ECDSA signature result
pub struct Signature {
    pub r: FieldElement,
    pub s: FieldElement,
    pub curve: Rc<CryptographicCurve>
}

impl Signature {
    pub fn new(r: FieldElement, s: FieldElement, curve: &Rc<CryptographicCurve>) -> Signature {
        Signature { r: r, s: s, curve: curve.clone() }
    }

    /// Verify the given signature against a public key and message hash
    pub fn verify(&self, public_key: &Point, message_hash: &FieldElement) -> bool {
        let u = message_hash / &self.s;
        let v = &self.r / &self.s;
        let total = &u * &self.curve.generator_point + &v * public_key;

        // The x coordinate of the resulting point should match the r value of
        // the signature
        if let Some(x) = total.x {
            x.value == self.r.value
        } else {
            false
        }
    }
}

/// ECDSA private key
pub struct PrivateKey {
    pub secret: FieldElement,
    pub public_key: Point,
    curve: Rc<CryptographicCurve>
}

impl PrivateKey {
    /// Create a new private key from the given secret on the given curve
    pub fn new(secret: FieldElement, curve: &Rc<CryptographicCurve>) -> PrivateKey {
        PrivateKey {
            secret: secret.clone(),
            public_key: &secret * &curve.generator_point,
            curve: curve.clone()
        }
    }

    //// Sign the given message using the given nonce
    pub fn sign(&self, nonce: &Integer, message: &Integer) -> Signature {
        let z = self.curve.make_element(message.clone());
        let k = self.curve.make_element(nonce.clone());

        // NOTE: We need the r coordinate as an integer value and not a field
        // element in for all of the math to work below.
        let r = (&k * &self.curve.generator_point).x.unwrap().value;
        let mut s = (z + (&r * &self.secret)) / k;

        if s.value > Integer::from(&self.curve.order.prime / 2) {
            s.value = &self.curve.order.prime - s.value;
        }

        Signature::new(self.curve.make_element(r), s, &self.curve)
    }
}

/// RFC-6979 nonce generator.
///
/// Returns a nonce [Integer] deterministically given a message and private
/// key.
pub fn nonce_generator_rfc6979(message: &Vec<u8>,
                               private_key: &Vec<u8>,
                               curve_order: &Integer) -> Integer
{
    // h1 = H(m) -- the hash of the given message
    let h1 = sha256(message.as_slice());

    // v = 0x01 0x01 .. 0x01 -- 32 0x01 bytes
    let mut v: Vec<u8> = iter::repeat(0x01).take(32).collect();

    // k = 0x00 0x00 .. 0x00 -- 32 0x00 bytes
    let mut k: Vec<u8> = iter::repeat(0x00).take(32).collect();

    // k = HMAC_K(V || 0x00 || int2octets(private_key) || bits2octets(h1))
    let mut hmac_input = v.clone();
    hmac_input.push(0x00);
    hmac_input.append(&mut private_key.clone());
    hmac_input.append(&mut h1.clone());
    k = hmac_sha256(&k, &hmac_input);

    // v = HMAC_K(v)
    v = hmac_sha256(&k, &v);

    // t = empty string
    let mut t : Vec<u8> = Vec::new();
    let mut result = Integer::with_capacity(256);

    // Loop until we find a suitable nonce
    loop {
        // v = HMAC_K(v)
        v = hmac_sha256(&k, &v);

        // t = t || v
        t.append(&mut v.clone());

        // If 0 < bits2int(t) < q - 1 -- t value in order of curve
        result.assign_digits(v.clone().as_slice(), Order::Msf);
        if result >= 1 && result < *curve_order {
            // Return t
            return result;
        }

        // Otherwise, k = HMAC_K(v || 0x00)
        hmac_input = v.clone();
        hmac_input.push(0x00);
        k = hmac_sha256(&k, &hmac_input);

        // v = HMAC_K(v)
        v = hmac_sha256(&k, &v);
    }
}

#[test]
fn test_signature_verification() {
    let curve = Rc::new(CryptographicCurve::new_secp256k1());
    let point = curve.make_point_integral(
        Integer::from_str_radix(
            "887387e452b8eacc4acfde10d9aaf7f6d9a0f975aabb10d006e4da568744d06c", 16
        ).unwrap(),
        Integer::from_str_radix(
            "61de6d95231cd89026e286df3b6ae4a894a3378e393e93a0f45b666329a0ae34", 16
        ).unwrap()
    ).unwrap();
    let signatures = vec![
        (
            "ec208baa0fc1c19f708a9ca96fdeff3ac3f230bb4a7ba4aede4942ad003c0f60",
            "ac8d1c87e51d0d441be8b3dd5b05c8795b48875dffe00b7ffcfac23010d3a395",
            "68342ceff8935ededd102dd876ffd6ba72d6a427a3edb13d26eb0781cb423c4"
        ),
        (
            "7c076ff316692a3d7eb3c3bb0f8b1488cf72e1afcd929e29307032997a838a3d",
            "eff69ef2b1bd93a66ed5219add4fb51e11a840f404876325a1e8ffe0529a2c",
            "c7207fee197d27c618aea621406f6bf5ef6fca38681d82b2f06fddbdce6feab6"
        )
    ];

    for (z_raw, r_raw, s_raw) in signatures {
        let z = curve.make_element(Integer::from_str_radix(z_raw, 16).unwrap());
        let r = curve.make_element(Integer::from_str_radix(r_raw, 16).unwrap());
        let s = curve.make_element(Integer::from_str_radix(s_raw, 16).unwrap());

        let signature = Signature::new(r, s, &curve);
        assert!(signature.verify(&point, &z));
    }
}

#[test]
fn test_signing() {
    use programmingbitcoin::messagedigest::*;

    let expectations = vec![
        (
            "my secret",
            "my message",
            1234567890,
            "2b698a0f0a4041b77e63488ad48c23e8e8838dd1fb7520408b121697b782ef22",
            "44eb19fd1061c078d1da052cd7b994c9d43b916c9f7b4789d46f0a44d087b488"
        )
    ];

    let curve = Rc::new(CryptographicCurve::new_secp256k1());
    for (secret, msg, nonce, r, s) in expectations {
        let e = curve.make_element(hash256_integer(secret.as_bytes()));
        let priv_key = PrivateKey::new(e.clone(), &curve);
        let msg_hash = hash256_integer(msg.as_bytes());
        let sig = priv_key.sign(&Integer::from(nonce), &msg_hash);

        assert_eq!(sig.r.value, Integer::from_str_radix(r, 16).unwrap());
        assert_eq!(sig.s.value, Integer::from_str_radix(s, 16).unwrap());
        assert!(sig.verify(&priv_key.public_key, &curve.make_element(msg_hash)));
    }
}
