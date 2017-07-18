use {Error, std};
use std::ascii::AsciiExt;

macro_rules! type_table {

    (QTYPE {
        $($(#[$q_meta:meta])* ($q_u16:expr, $q_text:expr, $q_id:ident),)*
     },
     TYPE {
        $($(#[$meta:meta])* ($u16:expr, $text:ident),)*
     } ) => {

        /// The `rtype` module defines well known TYPE constants.
        pub mod rtype {
            use super::RType;

            $(
                $( #[$meta] )*
                pub const $text: RType = RType($u16);
            )*
        }

        fn type_u16_to_str(n: u16) -> Option<&'static str> {
            match n {
                $($u16 => Some(stringify!($text)),)*
                _ => None,
            }
        }

        fn type_str_to_u16(s: &str) -> Option<u16> {
            $( if s.eq_ignore_ascii_case(stringify!($text)) {
                return Some($u16);
            } )*
            None
        }

        /// The `qtype` module defines well known QTYPE constants.
        pub mod qtype {
            use super::QType;

            $(
                $( #[$meta] )*
                pub const $text: QType = QType($u16);
            )*

            $(
                $( #[$q_meta] )*
                pub const $q_id: QType = QType($q_u16);
            )*
        }

        fn qtype_u16_to_str(n: u16) -> Option<&'static str> {
            type_u16_to_str(n).or_else(||
                match n {
                    $($q_u16 => Some($q_text),)*
                    _ => None,
                }
            )
        }

        fn qtype_str_to_u16(s: &str) -> Option<u16> {
            type_str_to_u16(s).or_else(|| {
                $( if s.eq_ignore_ascii_case($q_text) {
                    return Some($q_u16);
                } )*
                None
            } )
        }
    }
}

type_table!(

    QTYPE {

        /// Request to transfer a zone.
        (252, "AXFR", AXFR),

        /// Request for all records.
        (255, "*", ANY),
    },

    TYPE {

        /// Host address.
        (1, A),

        /// Authoritative name server.
        (2, NS),

        /// Canonical name.
        (5, CNAME),

        /// Start of a zone of authority.
        (6, SOA),

        /// Well known service description.
        (11, WKS),

        /// Domain name pointer.
        (12, PTR),

        /// Host information.
        (13, HINFO),

        /// Mailbox or mail list information.
        (14, MINFO),

        /// Mail exchange.
        (15, MX),

        /// Text.
        (16, TXT),
    }
);

/// `RType` stores the numeric value of a TYPE field in a resource record.
///
/// `RType` may store any `u16` TYPE value, but it supports text-and-number
/// conversions only for well known TYPE mnemonics.
///
/// # Examples
///
/// ```
/// use sparkle::RType;
///
/// // Convert from number to text.
/// assert_eq!(RType(6).to_text(), Some("SOA"));
/// assert_eq!(RType(1).to_text(), Some("A"));
///
/// // Convert from text to number.
/// assert_eq!(RType::parse_text("SOA").unwrap().as_u16(), 6);
/// assert_eq!(RType::parse_text("A").unwrap().as_u16(), 1);
///
/// // Mnemonics are case-insensitive.
/// assert_eq!(RType::parse_text("sOa").unwrap().to_text(), Some("SOA"));
///
/// // Unrecognized mnemonics result in a conversion error.
/// assert!(RType::parse_text("something unrecognized").is_err());
/// ```
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct RType(pub u16);

impl RType {
    /// The `parse_text` method converts a TYPE text mnemonic to its numeric
    /// value, if the mnemonic is known.
    pub fn parse_text(s: &str) -> Result<Self, Error> {
        type_str_to_u16(s).map(|x| RType(x)).ok_or(
            Error::new("The TYPE value is invalid or unsupported")
                .tag_as_bad_input()
                .into(),
        )
    }

    /// The `as_u16` method returns the TYPE as a `u16` type.
    pub fn as_u16(&self) -> u16 {
        self.0
    }

    /// The `to_text` method converts a TYPE numeric value to its uppercase text
    /// mnemonic, if the mnemonic is known.
    pub fn to_text(&self) -> Option<&'static str> {
        type_u16_to_str(self.0)
    }
}

impl std::str::FromStr for RType {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        RType::parse_text(s)
    }
}

/// `QType` stores the numeric value of a QTYPE field in a DNS query.
///
/// `QType` may store any `u16` QTYPE value, but it supports text-and-number
/// conversions only for well known QTYPE mnemonics.
///
/// # Examples
///
/// ```
/// use sparkle::{QType, RType};
///
/// // Convert from number to text.
/// assert_eq!(QType(6).to_text(), Some("SOA"));
/// assert_eq!(QType(255).to_text(), Some("*"));
///
/// // Convert from text to number.
/// assert_eq!(QType::parse_text("SOA").unwrap().as_u16(), 6);
/// assert_eq!(QType::parse_text("*").unwrap().as_u16(), 255);
///
/// // Mnemonics are case-insensitive.
/// assert_eq!(QType::parse_text("sOa").unwrap().to_text(), Some("SOA"));
///
/// // Unrecognized mnemonics result in a conversion error.
/// assert!(QType::parse_text("something unrecognized").is_err());
///
/// // A RType may be converted into a QType, but not vice-versa.
/// assert_eq!(QType::from(RType(6)).to_text(), Some("SOA"));
///
/// ```
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct QType(pub u16);

impl QType {
    /// The `parse_text` method converts a QTYPE text mnemonic to its numeric
    /// value, if the mnemonic is known.
    pub fn parse_text(s: &str) -> Result<Self, Error> {
        qtype_str_to_u16(s).map(|x| QType(x)).ok_or(
            Error::new("The QTYPE value is invalid or unsupported")
                .tag_as_bad_input()
                .into(),
        )
    }

    /// The `as_u16` method returns the QTYPE as a `u16` type.
    pub fn as_u16(&self) -> u16 {
        self.0
    }

    /// The `to_text` method converts a QTYPE numeric value to its uppercase
    /// text mnemonic, if the mnemonic is known.
    pub fn to_text(&self) -> Option<&'static str> {
        qtype_u16_to_str(self.0)
    }
}

impl std::str::FromStr for QType {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        QType::parse_text(s)
    }
}

impl From<RType> for QType {
    fn from(x: RType) -> Self {
        QType(x.0)
    }
}
