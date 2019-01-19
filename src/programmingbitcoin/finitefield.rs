//! Defines data structures and operations on finite fields and their elements
use rug::Integer;
use std::ops::{Add, Div, Mul, Sub};
use std::rc::Rc;

/// A Galois field with a prime integer modulus.
#[derive(Clone, Debug, PartialEq)]
pub struct GaloisField {
    pub prime: Integer
}

impl GaloisField {
    /// Create a new Galois field over the given prime modulus.
    pub fn new(prime: Integer) -> GaloisField {
        GaloisField { prime: prime }
    }

    /// Returns the equivalent value of the given integer in this field.
    ///
    /// The value is found by taking the value modulus the prime that defines
    /// the Galois field.
    pub fn value_of(&self, value: Integer) -> Integer {
        if value < Integer::from(0) || value >= self.prime {
            let result = value.div_rem_euc_ref(&self.prime);
            let (_, normalized_value) = <(Integer, Integer)>::from(result);
            normalized_value
        } else {
            value
        }
    }
}

/// Represents an element in a Galois Field.
#[derive(Clone, Debug, PartialEq)]
pub struct FieldElement {
    pub value: Integer,
    pub field: Rc<GaloisField>
}

impl FieldElement {
    /// Initialize a new element. If value > field.prime then its modulus is
    /// taken against field.prime to yield its value within the Galois field.
    pub fn new(value: Integer, field: &Rc<GaloisField>) -> FieldElement {
        // Otherwise, simply use the value as is
        FieldElement { value: field.value_of(value), field: field.clone() }
    }

    // Raise the current field element to the given integer power.
    pub fn pow(&self, exponent: &Integer) -> FieldElement {
        if self.field.prime == Integer::from(1) {
            return FieldElement::new(Integer::from(0), &self.field.clone());
        }

        if let Some(result) = self.value.pow_mod_ref(exponent, &self.field.prime) {
            FieldElement::new(Integer::from(result), &self.field.clone())
        } else {
            unreachable!()
        }
    }

    /// Indicates whether or not this field element is zero
    pub fn is_zero(&self) -> bool {
        self.value == 0
    }
}

impl Add for FieldElement {
    type Output = FieldElement;

    fn add(self, other: FieldElement) -> FieldElement {
        FieldElement::new(self.value + other.value, &self.field)
    }
}

impl<'a, 'b> Add<&'b FieldElement> for &'a FieldElement {
    type Output = FieldElement;

    fn add(self, other: &'b FieldElement) -> FieldElement {
        FieldElement::new(
            Integer::from(&self.value + &other.value),
            &self.field
        )
    }
}

impl<'a, 'b> Add<&'b FieldElement> for &'a Integer {
    type Output = FieldElement;

    fn add(self, other: &'b FieldElement) -> FieldElement {
        FieldElement::new(
            Integer::from(self + &other.value),
            &other.field
        )
    }
}

impl<'a> Add<&'a Integer> for FieldElement {
    type Output = FieldElement;

    fn add(self, other: &'a Integer) -> FieldElement {
        FieldElement::new(
            Integer::from(&self.value + other),
            &self.field
        )
    }
}

impl Sub for FieldElement {
    type Output = FieldElement;

    fn sub(self, other: FieldElement) -> FieldElement {
        FieldElement::new(self.value - other.value, &self.field)
    }
}

impl<'a> Sub<&'a FieldElement> for FieldElement {
    type Output = FieldElement;

    fn sub(self, other: &'a FieldElement) -> FieldElement {
        FieldElement::new(
            Integer::from(&self.value - &other.value),
            &self.field
        )
    }
}

impl<'a> Sub<FieldElement> for &'a FieldElement {
    type Output = FieldElement;

    fn sub(self, other: FieldElement) -> FieldElement {
        FieldElement::new(
            Integer::from(&self.value - &other.value),
            &self.field
        )
    }
}

impl<'a, 'b> Sub<&'b FieldElement> for &'a FieldElement {
    type Output = FieldElement;

    fn sub(self, other: &'b FieldElement) -> FieldElement {
        FieldElement::new(
            Integer::from(&self.value - &other.value),
            &self.field
        )
    }
}

impl Mul for FieldElement {
    type Output = FieldElement;

    fn mul(self, other: FieldElement) -> FieldElement {
        FieldElement::new(self.value * other.value, &self.field)
    }
}

impl Mul<FieldElement> for Integer {
    type Output = FieldElement;

    fn mul(self, other: FieldElement) -> FieldElement {
        FieldElement::new(self * other.value, &other.field)
    }
}

impl Mul<Integer> for FieldElement {
    type Output = FieldElement;

    fn mul(self, other: Integer) -> FieldElement {
        FieldElement::new(self.value * other, &self.field)
    }
}

impl<'a> Mul<FieldElement> for &'a FieldElement {
    type Output = FieldElement;

    fn mul(self, other: FieldElement) -> FieldElement {
        FieldElement::new(&self.value * other.value, &self.field)
    }
}

impl<'a, 'b> Mul<&'b Integer> for &'a FieldElement {
    type Output = FieldElement;

    fn mul(self, other: &'b Integer) -> FieldElement {
        FieldElement::new(
            Integer::from(&self.value * other),
            &self.field
        )
    }
}

impl<'a, 'b> Mul<&'b FieldElement> for &'a Integer {
    type Output = FieldElement;

    fn mul(self, other: &'b FieldElement) -> FieldElement {
        FieldElement::new(
            Integer::from(self * &other.value),
            &other.field
        )
    }
}

impl<'a> Mul<&'a FieldElement> for u32 {
    type Output = FieldElement;

    fn mul(self, other: &'a FieldElement) -> FieldElement {
        FieldElement::new(
            Integer::from(Integer::from(self) * &other.value),
            &other.field
        )
    }
}

impl<'a, 'b> Mul<&'b FieldElement> for &'a FieldElement {
    type Output = FieldElement;

    fn mul(self, other: &'b FieldElement) -> FieldElement {
        FieldElement::new(
            Integer::from(&self.value * &other.value),
            &self.field
        )
    }
}

impl Div for FieldElement {
    type Output = FieldElement;

    fn div(self, other: FieldElement) -> FieldElement {
        if let Ok(inv) = other.value.clone().invert(&self.field.prime) {
            FieldElement::new(
                self.value * &inv,
                &self.field
            )
        } else {
            unreachable!()
        }
    }
}

impl Div<Integer> for FieldElement {
    type Output = FieldElement;

    fn div(self, other: Integer) -> FieldElement {
        if let Ok(inv) = other.invert(&self.field.prime) {
            FieldElement::new(
                self.value * &inv,
                &self.field
            )
        } else {
            unreachable!()
        }
    }
}

impl<'a, 'b> Div<&'b FieldElement> for &'a FieldElement {
    type Output = FieldElement;

    fn div(self, other: &'b FieldElement) -> FieldElement {
        if let Ok(inv) = other.value.clone().invert(&self.field.prime) {
            FieldElement::new(
                Integer::from(&self.value * &inv),
                &self.field
            )
        } else {
            unreachable!()
        }
    }
}

#[test]
fn test_galois_fields() {
    let field = GaloisField::new(Integer::from(19));

    assert_eq!(field.value_of(Integer::from(0)), Integer::from(0));
    assert_eq!(field.value_of(Integer::from(19)), Integer::from(0));
    assert_eq!(field.value_of(Integer::from(17)), Integer::from(17));
    assert_eq!(field.value_of(Integer::from(191)), Integer::from(1));
}

#[test]
fn test_fieldelement_add() {
    let gf_223 = Rc::new(GaloisField::new(Integer::from(223)));
    let gf_19 = Rc::new(GaloisField::new(Integer::from(19)));

    let el1 = FieldElement::new(Integer::from(12), &gf_223.clone());
    let el2 = FieldElement::new(Integer::from(222), &gf_223.clone());
    assert_eq!(&el1 + &el2, FieldElement::new(Integer::from(11), &gf_223.clone()));

    let el1 = FieldElement::new(Integer::from(11), &gf_19.clone());
    let el2 = FieldElement::new(Integer::from(17), &gf_19.clone());
    assert_eq!(&el1 + &el2, FieldElement::new(Integer::from(9), &gf_19.clone()));

    let el1 = FieldElement::new(Integer::from(123), &gf_223.clone());
    let el2 = FieldElement::new(Integer::from(110), &gf_223.clone());
    assert_eq!(el1 + el2, FieldElement::new(Integer::from(10), &gf_223.clone()));
}

#[test]
fn test_fieldelement_sub() {
    let gf_223 = Rc::new(GaloisField::new(Integer::from(223)));

    let el1 = FieldElement::new(Integer::from(123), &gf_223.clone());
    let el2 = FieldElement::new(Integer::from(110), &gf_223.clone());
    assert_eq!(&el1 - &el2, FieldElement::new(Integer::from(13), &gf_223.clone()));
    assert_eq!(el2 - el1, FieldElement::new(Integer::from(210), &gf_223.clone()));
}

#[test]
fn test_fieldelement_mul() {
    let gf_223 = Rc::new(GaloisField::new(Integer::from(223)));
    let gf_19 = Rc::new(GaloisField::new(Integer::from(19)));

    let el1 = FieldElement::new(Integer::from(123), &gf_223.clone());
    let el2 = FieldElement::new(Integer::from(110), &gf_223.clone());
    assert_eq!(&el1 * &el2, FieldElement::new(Integer::from(150), &gf_223.clone()));

    let el1 = FieldElement::new(Integer::from(7), &gf_19.clone());
    let el2 = FieldElement::new(Integer::from(7), &gf_19.clone());
    let el3 = FieldElement::new(Integer::from(7), &gf_19.clone());
    assert_eq!(&el1 * &el2 * el3, FieldElement::new(Integer::from(1), &gf_19.clone()));
}

#[test]
fn test_fieldelement_div() {
    let gf_223 = Rc::new(GaloisField::new(Integer::from(223)));
    let gf_19 = Rc::new(GaloisField::new(Integer::from(19)));

    let el1 = FieldElement::new(Integer::from(123), &gf_223.clone());
    let el2 = FieldElement::new(Integer::from(110), &gf_223.clone());
    assert_eq!(&el1 / &el2, FieldElement::new(Integer::from(141), &gf_223.clone()));

    let el1 = FieldElement::new(Integer::from(2), &gf_19.clone());
    let el2 = FieldElement::new(Integer::from(7), &gf_19.clone());
    assert_eq!(&el1 / &el2, FieldElement::new(Integer::from(3), &gf_19.clone()));

    let el1 = FieldElement::new(Integer::from(7), &gf_19.clone());
    let el2 = FieldElement::new(Integer::from(5), &gf_19.clone());
    assert_eq!(el1 / el2, FieldElement::new(Integer::from(9), &gf_19.clone()));
}

#[test]
fn test_pow() {
    let gf_19 = Rc::new(GaloisField::new(Integer::from(19)));

    let n = FieldElement::new(Integer::from(7), &gf_19.clone());
    assert_eq!(n.pow(&Integer::from(3)), FieldElement::new(Integer::from(1), &gf_19.clone()));

    let n = FieldElement::new(Integer::from(9), &gf_19.clone());
    assert_eq!(n.pow(&Integer::from(12)), FieldElement::new(Integer::from(7), &gf_19.clone()));
}
