use std;

const MAX: u32 = 0x_8000_0000;

/// `Serial` stores a zone serial number.
///
/// A zone serial number is an unsigned 32-bit number that denotes a zone's
/// version.
///
/// The `Serial` type safely overflows on addition and uses **sequence space
/// arithmetic** for comparison, as defined in [RFC 1982][rfc_1982]. The
/// example, below, demonstrates this.
///
/// # Examples
///
/// ```
/// use sparkle::Serial;
///
/// // Serial addition safely overflows.
/// assert_eq!(Serial(0) + 1, Serial(1));
/// assert_eq!(Serial(0xffff_ffff) + 1, Serial(0));
/// assert_eq!(Serial(0xffff_ffff) + 2, Serial(1));
///
/// // However, Serial comparison effectively ignores overflow.
/// assert!(Serial(0) < Serial(1));
/// assert!(Serial(0xffff_fffe) < Serial(0xffff_ffff));
/// assert!(Serial(0xffff_ffff) < Serial(0));
///
/// // One consequence is that antipodal values do not have a defined
/// // ordering.
/// assert!(!(Serial(0) < Serial(0x8000_0000)));
/// assert!(!(Serial(0x8000_0000) < Serial(0)));
///
/// // Nonetheless, Serial implements full equality--even for antipodal
/// // values.
/// assert_eq!(Serial(0), Serial(0));
/// assert_ne!(Serial(0), Serial(0x8000_0000));
/// ```
///
/// [rfc_1982]: https://tools.ietf.org/html/rfc1982
///
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct Serial(pub u32);

impl Serial {
    /// The `as_u32` method returns the serial number as a `u32` type.
    pub fn as_u32(&self) -> u32 {
        self.0
    }
}

impl std::fmt::Display for Serial {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> Result<(), std::fmt::Error> {
        self.0.fmt(f)
    }
}

impl From<Serial> for u32 {
    fn from(x: Serial) -> Self {
        x.0
    }
}

impl PartialOrd for Serial {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {

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

impl std::ops::Add<u32> for Serial {
    type Output = Self;
    fn add(self, other: u32) -> Self::Output {
        debug_assert!(other < MAX);
        Serial(self.0.wrapping_add(other))
    }
}

impl std::ops::AddAssign<u32> for Serial {
    fn add_assign(&mut self, other: u32) {
        debug_assert!(other < MAX);
        self.0 = self.0.wrapping_add(other);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn displays_as_decimal_number() {
        let got = format!("{}", Serial(1234));
        let expected = "1234";
        assert_eq!(got, expected);
    }

    #[test]
    fn u32_from_serial_is_inner_value() {
        let x = Serial(1234);
        let got = u32::from(x);
        let expected = 1234;
        assert_eq!(got, expected);
    }

    fn tc_partial_cmp_impl(lhs: u32, rhs: u32, expected: Option<std::cmp::Ordering>) {
        use std::cmp::Ordering::*;
        let (forward, reverse) = match expected {
            Some(Equal) => (Some(Equal), Some(Equal)),
            Some(Less) => (Some(Less), Some(Greater)),
            Some(Greater) => (Some(Greater), Some(Less)),
            None => (None, None),
        };
        assert_eq!(Serial(lhs).partial_cmp(&Serial(rhs)), forward);
        assert_eq!(Serial(rhs).partial_cmp(&Serial(lhs)), reverse);
    }

    macro_rules! tc {
        ($test_name:ident, $lhs:expr, $rhs:expr, eq) => {
            #[test]
            fn $test_name() {
                tc_partial_cmp_impl($lhs, $rhs, Some(std::cmp::Ordering::Equal));
            }
        };
        ($test_name:ident, $lhs:expr, $rhs:expr, lt) => {
            #[test]
            fn $test_name() {
                tc_partial_cmp_impl($lhs, $rhs, Some(std::cmp::Ordering::Less));
            }
        };
        ($test_name:ident, $lhs:expr, $rhs:expr, none) => {
            #[test]
            fn $test_name() {
                tc_partial_cmp_impl($lhs, $rhs, None);
            }
        };
    }

    tc!(partial_cmp_0_eq_0, 0, 0, eq);
    tc!(
        partial_cmp_7fff_ffff_eq_7fff_ffff,
        0x7fff_ffff,
        0x7fff_ffff,
        eq
    );
    tc!(
        partial_cmp_8000_0000_eq_8000_8000,
        0x8000_0000,
        0x8000_0000,
        eq
    );
    tc!(
        partial_cmp_ffff_ffff_eq_ffff_ffff,
        0xffff_ffff,
        0xffff_ffff,
        eq
    );

    tc!(partial_cmp_0_lt_1, 0, 1, lt);
    tc!(partial_cmp_0_lt_42, 0, 42, lt);
    tc!(partial_cmp_0_gt_ffff_ffff, 0xffff_ffff, 0, lt);

    tc!(partial_cmp_0_lt_7fff_0000, 0, 0x7fff_ffff, lt);
    tc!(partial_cmp_0_xx_8000_0000, 0, 0x8000_0000, none);
    tc!(partial_cmp_0_gt_8000_0001, 0x8000_0001, 0, lt);
    tc!(partial_cmp_1_lt_8000_0000, 1, 0x8000_0000, lt);
    tc!(partial_cmp_1_xx_8000_0001, 1, 0x8000_0001, none);
    tc!(partial_cmp_1_gt_8000_0002, 0x8000_0002, 1, lt);

    tc!(
        partial_cmp_4000_0000_lt_bfff_ffff,
        0x4000_0000,
        0xbfff_ffff,
        lt
    );
    tc!(
        partial_cmp_4000_0000_xx_c000_0000,
        0x4000_0000,
        0xc000_0000,
        none
    );
    tc!(
        partial_cmp_4000_0000_xx_c000_0001,
        0xc000_0001,
        0x4000_0000,
        lt
    );

    macro_rules! tc {
        ($test_name:ident, $lhs:expr, $rhs:expr, $expected:expr) => {
            #[test]
            fn $test_name() {

                let expected = Serial($expected);

                let got = Serial($lhs) + $rhs;
                assert_eq!(got, expected);

                let mut got = Serial($lhs);
                got += $rhs;
                assert_eq!(got, expected);
            }
        };
    }

    tc!(add_0_and_0, 0, 0, 0);
    tc!(add_0_and_1, 0, 1, 1);
    tc!(add_0_and_42, 0, 42, 42);
    tc!(add_0_and_7fff_ffff, 0, 0x7fff_ffff, 0x7fff_ffff);
    tc!(add_ffff_ffff_and_1, 0xffff_ffff, 1, 0);
    tc!(add_ffff_ffff_and_2, 0xffff_ffff, 2, 1);
    tc!(
        add_ffff_ffff_and_7fff_ffff,
        0xffff_ffff,
        0x7fff_ffff,
        0x7fff_fffe
    );
}
