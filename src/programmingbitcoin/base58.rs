//! Base58 and Base58Check encoding and decoding
use std::iter;
use rug::Integer;
use rug::integer::Order;

static BASE58_ALPHABET : &'static [u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

pub fn base58_encode(val: Vec<u8>) -> Vec<u8> {
    let mut leading_zeros_count = 0;
    for ch in &val {
        println!("{:x}", ch);
        if *ch == 0 {
            leading_zeros_count += 1;
        } else {
            break;
        }
    }

    let prefix : Vec<u8> = iter::repeat('1' as u8).take(leading_zeros_count).collect();
    let mut num = Integer::from_digits::<u8>(&val[..], Order::MsfBe);
    let mut result : Vec<u8> = Vec::new();
    while num > 0 {
        let (val, rem) = <(Integer, Integer)>::from(num.div_rem_euc_ref(&Integer::from(58)));
        result.push(BASE58_ALPHABET[rem.to_u32().unwrap() as usize]);
        num = val;
    }
    result.reverse();

    println!("{:x?} - {}", prefix, leading_zeros_count);
    let mut final_value = prefix;
    final_value.extend(result);
    final_value
}

#[test]
fn test_base58_encoding() {
    let values = vec![
        (
            Integer::from_str_radix("7c076ff316692a3d7eb3c3bb0f8b1488cf72e1afcd929e29307032997a838a3d", 16).unwrap(),
            b"9MA8fRQrT4u8Zj8ZRd6MAiiyaxb2Y1CMpvVkHQu5hVM6"
        ),
        (
            Integer::from_str_radix("eff69ef2b1bd93a66ed5219add4fb51e11a840f404876325a1e8ffe0529a2c", 16).unwrap(),
            b"14fE3H2E6XMp4SsxtwinF7w9a34ooUrwWe4WsW1458Pd"
        ),
        (
            Integer::from_str_radix("c7207fee197d27c618aea621406f6bf5ef6fca38681d82b2f06fddbdce6feab6", 16).unwrap(),
            b"EQJsjkd6JaGwxrjEhfeqPenqHwrBmPQZjJGNSCHBkcF7"
        )
    ];

    for (val, expected_encoding) in values {
        let mut bytes = Integer::to_digits::<u8>(&val, Order::MsfBe);

        // Prepend any missing zero bytes before encoding
        while bytes.len() < 32 {
            let mut replacement = vec![0x00];
            replacement.extend(bytes);
            bytes = replacement;
            println!("{:x?}", bytes);
        }

        let mut result = base58_encode(bytes);
        assert_eq!(result, &expected_encoding[..]);
    }
}
