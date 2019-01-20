//! Contains traits for serializing values
use std::rc::Rc;
use rug::Integer;
use rug::ops::*;
use rug::integer::Order;

use programmingbitcoin::ellipticcurve::*;
use programmingbitcoin::ecdsa::*;

pub trait PublicKeySerialization {
    /// Converts a public key value into SEC format.
    fn as_sec(&self) -> Vec<u8>;
    /// Converts a public key value into compressed SEC format.
    fn as_compressed_sec(&self) -> Vec<u8>;
}

pub trait PublicKeyDeserialization {
    /// Convert an SEC serialized compressed or uncompressed address to a PublicKey
    fn from_sec(data: &Vec<u8>, curve: &Rc<CryptographicCurve>) -> Point;
}

impl PublicKeySerialization for Point {
    // SEC encode and given point
    fn as_sec(&self) -> Vec<u8> {
        let mut result : Vec<u8> = Vec::new();
        let x_val = self.x.clone().unwrap().value;
        let y_val = self.y.clone().unwrap().value;

        result.push(0x04);
        result.append(&mut x_val.to_digits::<u8>(Order::MsfBe));
        result.append(&mut y_val.to_digits::<u8>(Order::MsfBe));
        result
    }

    // Compressed SEC encode a given point
    fn as_compressed_sec(&self) -> Vec<u8> {
        let mut result : Vec<u8> = Vec::new();
        let x_val = self.x.clone().unwrap().value;
        let prefix_byte =
            if self.y.clone().unwrap().value.is_even() {
                0x02
            } else {
                0x03
            };

        result.push(prefix_byte);
        result.append(&mut x_val.to_digits::<u8>(Order::MsfBe));
        result
    }
}

impl Point {
    /// Load SEC formatted public key
    fn from_sec(data: &Vec<u8>, curve: &Rc<CryptographicCurve>) -> Point {
        // Uncompressed
        if data[0] == 0x4 {
            let x = Integer::from_digits::<u8>(&data[1..33], Order::MsfBe);
            let y = Integer::from_digits::<u8>(&data[33..65], Order::MsfBe);
            return curve.make_point_integral(x, y).unwrap();
        }

        // Compressed
        let is_even = data[0] == 0x2;
        let x = curve.finite_curve.make_element(
            Integer::from_digits::<u8>(&data[1..], Order::MsfBe)
        );
        let alpha = curve.finite_curve.make_element(
            x.clone().value.pow(3) + &curve.finite_curve.curve.b
        );
        let beta = alpha.sqrt();

        let mut even_beta = curve.finite_curve.make_element(beta.clone());
        let mut odd_beta = curve.finite_curve.make_element(beta.clone());
        if beta.is_even() {
            odd_beta = curve.finite_curve.make_element(Integer::from(&curve.finite_curve.field.prime - beta));
        } else {
            even_beta = curve.finite_curve.make_element(Integer::from(&curve.finite_curve.field.prime - beta.clone()));
        }

        if is_even {
            Point::new(Some(x), Some(even_beta), &curve.finite_curve)
        } else {
            Point::new(Some(x), Some(odd_beta), &curve.finite_curve)
        }
    }
}

#[test]
fn test_sec_serialization() {
    use rug::Integer;
    use std::rc::Rc;
    use programmingbitcoin::ecdsa::*;
    use rug::ops::*;

    let curve = Rc::new(CryptographicCurve::new_secp256k1());

    let values = vec![
        (
            Integer::from(5000),
            b"\x04\xff\xe5X\xe3\x88\x85/\x01 \xe4j\xf2\xd1\xb3p\xf8XT\xa8\xeb\x08A\x81\x1e\xce\x0e>\x03\xd2\x82\xd5|1]\xc7(\x90\xa4\xf1\n\x14\x81\xc01\xb0;5\x1b\r\xc7\x99\x01\xca\x18\xa0\x0c\xf0\t\xdb\xdb\x15z\x1d\x10",
            b"\x02\xff\xe5X\xe3\x88\x85/\x01 \xe4j\xf2\xd1\xb3p\xf8XT\xa8\xeb\x08A\x81\x1e\xce\x0e>\x03\xd2\x82\xd5|"
        ),
        (
            Integer::from(2018).pow(5),
            b"\x04\x02\x7f=\xa1\x91\x84U\xe0<F\xf6Y&j\x1b\xb5 N\x95\x9d\xb76M/G;\xdf\x8f\n\x13\xcc\x9d\xff\x87d\x7f\xd0#\xc1;JI\x94\xf1v\x91\x89X\x06\xe1\xb4\x0bW\xf4\xfd\"X\x1aOF\x85\x1f;\x06",
            b"\x02\x02\x7f=\xa1\x91\x84U\xe0<F\xf6Y&j\x1b\xb5 N\x95\x9d\xb76M/G;\xdf\x8f\n\x13\xcc\x9d"
        ),
        (
            Integer::from(0xdeadbeef12345i64),
            b"\x04\xd9\x0c\xd6%\xee\x87\xdd8em\xd9\\\xf7\x9fe\xf6\x0frs\xb6}0\x96\xe6\x8b\xd8\x1eOSBi\x1f\x84.\xfav/\xd5\x99a\xd0\xe9\x98\x03\xc6\x1e\xdb\xa8\xb3\xe3\xf7\xdc:4\x186\xf9w3\xae\xbf\x98q!",
            b"\x03\xd9\x0c\xd6%\xee\x87\xdd8em\xd9\\\xf7\x9fe\xf6\x0frs\xb6}0\x96\xe6\x8b\xd8\x1eOSBi\x1f"
        )
    ];
    for (secret, uncompressed, compressed) in values {
        let private_key = PrivateKey::new(curve.make_element(secret), &curve);
        let result = private_key.public_key.as_sec();
        assert_eq!(result.len(), 65);
        assert_eq!(result, &uncompressed[..]);

        let decoded = Point::from_sec(&result, &curve);
        assert_eq!(decoded, private_key.public_key);

        let result = private_key.public_key.as_compressed_sec();
        assert_eq!(result.len(), 33);
        assert_eq!(result, &compressed[..]);

        let decoded = Point::from_sec(&result, &curve);
        assert_eq!(decoded, private_key.public_key);
    }
}
