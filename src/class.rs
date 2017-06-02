use {Error, ErrorKind, std};
use std::ascii::AsciiExt;

macro_rules! class_table {

    (QCLASS {
        $($(#[$q_meta:meta])* ($q_u16:expr, $q_text:expr, $q_id:ident),)*
     },
     CLASS {
        $($(#[$meta:meta])* ($u16:expr, $text:ident),)*
     } ) => {

        /// The `rclass` module defines well known CLASS constants.
        pub mod rclass {
            use super::RClass;

            $(
                $( #[$meta] )*
                pub const $text: RClass = RClass($u16);
            )*
        }

        fn class_u16_to_str(n: u16) -> Option<&'static str> {
            match n {
                $($u16 => Some(stringify!($text)),)*
                _ => None,
            }
        }

        fn class_str_to_u16(s: &str) -> Option<u16> {
            $( if s.eq_ignore_ascii_case(stringify!($text)) {
                return Some($u16);
            } )*
            None
        }

        /// The `qclass` module defines well known QCLASS constants.
        pub mod qclass {
            use super::QClass;

            $(
                $( #[$meta] )*
                pub const $text: QClass = QClass($u16);
            )*

            $(
                $( #[$q_meta] )*
                pub const $q_id: QClass = QClass($q_u16);
            )*
        }

        fn qclass_u16_to_str(n: u16) -> Option<&'static str> {
            class_u16_to_str(n).or_else(||
                match n {
                    $($q_u16 => Some($q_text),)*
                    _ => None,
                }
            )
        }

        fn qclass_str_to_u16(s: &str) -> Option<u16> {
            class_str_to_u16(s).or_else(|| {
                $( if s.eq_ignore_ascii_case($q_text) {
                    return Some($q_u16);
                } )*
                None
            } )
        }
    }
}

class_table!(

    QCLASS {

        /// Request for any class.
        (255, "*", ANY),
    },

    CLASS {

        /// Internet.
        (1, IN),

        /// Chaosnet.
        (3, CHAOS),
    }
);

/// `RClass` stores the numeric value of a CLASS field in a resource record.
///
/// `RClass` may store any `u16` CLASS value, but it supports text-and-number
/// conversions only for well known CLASS mnemonics.
///
/// # Examples
///
/// ```
/// use sparkle::RClass;
///
/// // Convert from number to text.
/// assert_eq!(RClass(1).to_text(), Some("IN"));
/// assert_eq!(RClass(3).to_text(), Some("CHAOS"));
///
/// // Convert from text to number.
/// assert_eq!(RClass::parse_text("IN").unwrap().as_u16(), 1);
/// assert_eq!(RClass::parse_text("CHAOS").unwrap().as_u16(), 3);
///
/// // Mnemonics are case-insensitive.
/// assert_eq!(RClass::parse_text("iN").unwrap().to_text(), Some("IN"));
///
/// // Unrecognized mnemonics result in a conversion error.
/// assert!(RClass::parse_text("something unrecognized").is_err());
/// ```
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct RClass(pub u16);

impl RClass {
    /// The `parse_text` method converts a CLASS text mnemonic to its numeric
    /// value, if the mnemonic is known.
    pub fn parse_text(s: &str) -> Result<Self, Error> {
        class_str_to_u16(s)
            .map(|x| RClass(x))
            .ok_or(Error::new(ErrorKind::InvalidInput,
                              "The CLASS value is invalid or supported"))
    }

    /// The `as_u16` method returns the CLASS as a `u16` type.
    pub fn as_u16(&self) -> u16 {
        self.0
    }

    /// The `to_text` method converts a CLASS numeric value to its uppercase
    /// text mnemonic, if the mnemonic is known.
    pub fn to_text(&self) -> Option<&'static str> {
        class_u16_to_str(self.0)
    }
}

impl std::str::FromStr for RClass {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        RClass::parse_text(s)
    }
}

/// `QClass` stores the numeric value of a QCLASS field in a DNS query.
///
/// `QClass` may store any `u16` QCLASS value, but it supports text-and-number
/// conversions only for well known QCLASS mnemonics.
///
/// # Examples
///
/// ```
/// use sparkle::{QClass, RClass};
///
/// // Convert from number to text.
/// assert_eq!(QClass(1).to_text(), Some("IN"));
/// assert_eq!(QClass(255).to_text(), Some("*"));
///
/// // Convert from text to number.
/// assert_eq!(QClass::parse_text("IN").unwrap().as_u16(), 1);
/// assert_eq!(QClass::parse_text("*").unwrap().as_u16(), 255);
///
/// // Mnemonics are case-insensitive.
/// assert_eq!(QClass::parse_text("iN").unwrap().to_text(), Some("IN"));
///
/// // Unrecognized mnemonics result in a conversion error.
/// assert!(QClass::parse_text("something unrecognized").is_err());
///
/// // A RClass may be converted into a QClass, but not vice-versa.
/// assert_eq!(QClass::from(RClass(1)).to_text(), Some("IN"));
///
/// ```
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct QClass(pub u16);

impl QClass {
    /// The `parse_text` method converts a QCLASS text mnemonic to its numeric
    /// value, if the mnemonic is known.
    pub fn parse_text(s: &str) -> Result<Self, Error> {
        qclass_str_to_u16(s)
            .map(|x| QClass(x))
            .ok_or(Error::new(ErrorKind::InvalidInput,
                              "The QCLASS value is invalid or unsupported"))
    }

    /// The `as_u16` method returns the QCLASS as a `u16` type.
    pub fn as_u16(&self) -> u16 {
        self.0
    }

    /// The `to_text` method converts a QCLASS numeric value to its uppercase
    /// text mnemonic, if the mnemonic is known.
    pub fn to_text(&self) -> Option<&'static str> {
        qclass_u16_to_str(self.0)
    }
}

impl std::str::FromStr for QClass {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        QClass::parse_text(s)
    }
}

impl From<RClass> for QClass {
    fn from(x: RClass) -> Self {
        QClass(x.0)
    }
}
