use std;

const MAX: u32 = 0x_8000_0000;

/// Encapsulates a zone's serial number.
///
/// `SerialNumber` uses **sequence space arithmetic**, defined in [RFC
/// 1982](https://tools.ietf.org/html/rfc1982). Sequence space arithmetic
/// defines the *addition* and *comparison* operations such that the serial
/// number wraps on overflow while maintaining an intuitive and well defined
/// meaning for the operations' results.
///
/// # Examples
///
/// ```
/// use sparkle::SerialNumber;
///
/// let x = SerialNumber(0);
/// assert!(x < x + SerialNumber(1));
///
/// let x = SerialNumber(0x_ffff_ffff);
/// assert!(x < x + SerialNumber(1));
/// ```
///
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct SerialNumber(pub u32);

impl SerialNumber {
    pub fn as_u32(&self) -> u32 {
        self.0
    }
}

impl std::fmt::Display for SerialNumber {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> Result<(), std::fmt::Error> {
        self.0.fmt(f)
    }
}

impl From<SerialNumber> for u32 {
    fn from(x: SerialNumber) -> Self {
        x.0
    }
}

impl PartialOrd for SerialNumber {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {

        const MAX: u32 = 0x_8000_0000;

        let i1 = self.0; // same name used in RFC 1982
        let i2 = other.0; // same name used in RFC 1982

        if i1 == i2 {
            Some(std::cmp::Ordering::Equal)
        } else if (i1 < i2 && i2 - i1 < MAX) || (i1 > i2 && i1 - i2 > MAX) {
            Some(std::cmp::Ordering::Less)
        } else if (i1 < i2 && i2 - i1 > MAX) || (i1 > i2 && i1 - i2 < MAX) {
            Some(std::cmp::Ordering::Greater)
        } else {
            debug_assert!((i1 < i2 && i2 - i1 == 0x_8000_0000) || (i1 > i2 && i1 - i2 == 0x_8000_0000));

            // According to RFC 1982, section 3.2, implementations are free to
            // define any result for this condition.
            //
            // > Thus the problem case is left undefined, implementations are
            // free to return either result, or to flag an error, and users must
            // take care not to depend on any particular outcome. <

            None
        }
    }
}

impl std::ops::Add for SerialNumber {
    type Output = Self;
    fn add(self, other: Self) -> Self::Output {
        debug_assert!(other.0 < MAX);
        SerialNumber(self.0.wrapping_add(other.0))
    }
}

impl std::ops::AddAssign for SerialNumber {
    fn add_assign(&mut self, other: Self) {
        debug_assert!(other.0 < MAX);
        self.0 = self.0.wrapping_add(other.0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serial_number_display() {
        let got = format!("{}", SerialNumber(1234));
        let expected = "1234";
        assert_eq!(got, expected);
    }

    #[test]
    fn u32_from_serial_number() {
        let x = SerialNumber(1234);
        let got = u32::from(x);
        let expected = 1234;
        assert_eq!(got, expected);
    }

    #[test]
    fn serial_number_partial_cmp() {
        use std::cmp::Ordering::*;

        let f = |x, y| SerialNumber(x).partial_cmp(&SerialNumber(y));

        // Equality cases.

        assert_eq!(f(0, 0), Some(Equal));
        assert_eq!(f(1, 1), Some(Equal));
        assert_eq!(f(0x_7fff_ffff, 0x_7fff_ffff), Some(Equal));
        assert_eq!(f(0x_8000_0000, 0x_8000_0000), Some(Equal));
        assert_eq!(f(0x_ffff_ffff, 0x_ffff_ffff), Some(Equal));

        // Unequal-but-defined cases.

        assert_eq!(f(0, 1), Some(Less));
        assert_eq!(f(1, 0), Some(Greater));

        assert_eq!(f(0, 44), Some(Less));
        assert_eq!(f(44, 0), Some(Greater));

        assert_eq!(f(0, 100), Some(Less));
        assert_eq!(f(100, 0), Some(Greater));

        assert_eq!(f(44, 100), Some(Less));
        assert_eq!(f(100, 44), Some(Greater));

        assert_eq!(f(0x_ffff_ffff, 0x_0000_0000), Some(Less));
        assert_eq!(f(0x_0000_0000, 0x_ffff_ffff), Some(Greater));

        assert_eq!(f(0x_0000_0000, 0x_7fff_ffff), Some(Less));
        assert_eq!(f(0x_7fff_ffff, 0x_0000_0000), Some(Greater));

        assert_eq!(f(0x_0000_0001, 0x_8000_0000), Some(Less));
        assert_eq!(f(0x_8000_0000, 0x_0000_0001), Some(Greater));

        assert_eq!(f(0x_4000_0000, 0x_bfff_ffff), Some(Less));
        assert_eq!(f(0x_bfff_ffff, 0x_4000_0000), Some(Greater));

        // Undefined cases.

        assert_eq!(f(0x_0000_0000, 0x_8000_0000), None);
        assert_eq!(f(0x_8000_0000, 0x_0000_0000), None);

        assert_eq!(f(0x_0000_0001, 0x_8000_0001), None);
        assert_eq!(f(0x_8000_0001, 0x_0000_0001), None);

        assert_eq!(f(0x_4000_0000, 0x_c000_0000), None);
        assert_eq!(f(0x_c000_0000, 0x_4000_0000), None);

        assert_eq!(f(0x_7fff_ffff, 0x_ffff_ffff), None);
        assert_eq!(f(0x_ffff_ffff, 0x_7fff_ffff), None);
    }

    #[test]
    fn serial_number_add() {
        let f = |x, y| SerialNumber(x) + SerialNumber(y);
        assert_eq!(f(0, 0), SerialNumber(0));
        assert_eq!(f(0, 1), SerialNumber(1));
        assert_eq!(f(0, 42), SerialNumber(42));
        assert_eq!(f(0, 0x_7fff_ffff), SerialNumber(0x_7fff_ffff));
        assert_eq!(f(0x_ffff_ffff, 1), SerialNumber(0));
        assert_eq!(f(0x_ffff_ffff, 2), SerialNumber(1));
        assert_eq!(f(0x_ffff_ffff, 0x_7fff_ffff), SerialNumber(0x_7fff_fffe));
    }

    #[test]
    fn serial_number_add_assign() {
        let f = |x, y| {
            let mut x = SerialNumber(x);
            x += SerialNumber(y);
            x
        };
        assert_eq!(f(0, 0), SerialNumber(0));
        assert_eq!(f(0, 1), SerialNumber(1));
        assert_eq!(f(0, 42), SerialNumber(42));
        assert_eq!(f(0, 0x_7fff_ffff), SerialNumber(0x_7fff_ffff));
        assert_eq!(f(0x_ffff_ffff, 1), SerialNumber(0));
        assert_eq!(f(0x_ffff_ffff, 2), SerialNumber(1));
        assert_eq!(f(0x_ffff_ffff, 0x_7fff_ffff), SerialNumber(0x_7fff_fffe));
    }
}
