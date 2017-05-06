use {SerialNumber, Ttl, std};

/// Associates the set of DNS types for a common format.
pub trait Format<'a> {
    type Name: Name<'a>;
    type RawOctets: AsRef<[u8]> + Clone + std::fmt::Debug + Eq + PartialEq;
}

/// Encapsulates a domain name.
pub trait Name<'a>: std::fmt::Display {
    type LabelIter: Iterator<Item = &'a str>;
    fn labels(&'a self) -> Self::LabelIter;
}

/// Encapsulates a question stored in a given format.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Question<'a, F: Format<'a>> {
    qname: F::Name,
    qtype: QType,
    qclass: QClass,
}

impl<'a, F: Format<'a>> Question<'a, F> {
    pub fn new<N: Into<F::Name>>(qname: N, qtype: QType, qclass: QClass) -> Self {
        Question {
            qname: qname.into(),
            qtype: qtype,
            qclass: qclass,
        }
    }

    pub fn qname(&self) -> &F::Name {
        &self.qname
    }

    pub fn qtype(&self) -> QType {
        self.qtype
    }

    pub fn qclass(&self) -> QClass {
        self.qclass
    }
}

/// Encapsulates a resource record stored in a given format.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResourceRecord<'a, F: Format<'a>> {
    name: F::Name,
    type_: Type,
    class: Class,
    ttl: Ttl,
    rdata: RData<'a, F>,
}

impl<'a, F: Format<'a>> ResourceRecord<'a, F> {
    pub fn new<N: Into<F::Name>, IntoT: Into<Ttl>, R: Into<RData<'a, F>>>(name: N,
                                                                          type_: Type,
                                                                          class: Class,
                                                                          ttl: IntoT,
                                                                          rdata: R)
                                                                          -> Self {
        ResourceRecord {
            name: name.into(),
            type_: type_,
            class: class,
            ttl: ttl.into(),
            rdata: rdata.into(),
        }
    }

    pub fn name(&self) -> &F::Name {
        &self.name
    }

    pub fn type_(&self) -> Type {
        self.type_
    }

    pub fn class(&self) -> Class {
        self.class
    }

    pub fn ttl(&self) -> Ttl {
        self.ttl
    }

    pub fn rdata(&self) -> &RData<'a, F> {
        &self.rdata
    }
}

/// Encapsulates an RDATA field stored in a given format.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RData<'a, F: Format<'a>> {
    A { address: std::net::Ipv4Addr },
    CName { cname: F::Name },
    NS { nsdname: F::Name },
    SOA {
        mname: F::Name,
        rname: F::Name,
        serial: SerialNumber,
        refresh: Ttl,
        retry: Ttl,
        expire: Ttl,
        minimum: Ttl,
    },
    Other { octets: F::RawOctets },
}

/// Encapsulates a CLASS value.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct Class(pub u16);

impl Class {
    /// Returns the underlying CLASS value.
    pub fn as_u16(&self) -> u16 {
        self.0
    }
}

/// Encapsulates a QCLASS value.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct QClass(pub u16);

impl QClass {
    /// Returns the underlying QCLASS value.
    pub fn as_u16(&self) -> u16 {
        self.0
    }
}

impl From<QClass> for Class {
    fn from(x: QClass) -> Self {
        Class(x.0)
    }
}

/// Defines well known CLASS values.
pub mod class {
    use super::Class;

    /// Specifies the **Internet** class.
    pub const IN: Class = Class(1);
}

/// Defines well known QCLASS values.
pub mod qclass {
    use super::QClass;

    /// Specifies the **Internet** class.
    pub const IN: QClass = QClass(1);

    /// Specifies the **wildcard** (`*`) class.
    pub const ANY: QClass = QClass(255);
}

/// Encapsulates a TYPE value.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct Type(pub u16);

impl Type {
    /// Returns the underlying TYPE value.
    pub fn as_u16(&self) -> u16 {
        self.0
    }
}

/// Encapsulates a QTYPE value.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct QType(pub u16);

impl QType {
    /// Returns the underlying QTYPE value.
    pub fn as_u16(&self) -> u16 {
        self.0
    }
}

impl From<QType> for Type {
    fn from(x: QType) -> Self {
        Type(x.0)
    }
}

/// Defines well known TYPE values.
pub mod type_ {
    use super::Type;

    /// Specifies the **Internet IPv4 address** record type.
    pub const A: Type = Type(1);

    /// Specifies the **name server** record type.
    pub const NS: Type = Type(2);

    /// Specifies the **canonical name** record type.
    pub const CNAME: Type = Type(5);

    /// Specifies the **start of authority** record type.
    pub const SOA: Type = Type(6);
}

/// Defines well known QTYPE values.
pub mod qtype {
    use super::QType;

    /// Specifies the **Internet IPv4 address** record type.
    pub const A: QType = QType(1);

    /// Specifies the **name server** record type.
    pub const NS: QType = QType(2);

    /// Specifies the **canonical name** record type.
    pub const CNAME: QType = QType(5);

    /// Specifies the **start of authority** record type.
    pub const SOA: QType = QType(6);

    /// Specifies the **wildcard** (`*`) record type.
    pub const ANY: QType = QType(255);
}

pub fn is_label_valid(s: &[u8]) -> bool {
    debug_assert!(!s.is_empty());
    let c = *s.first().unwrap() as char;
    if !c.is_alphabetic() {
        return false;
    }
    let c = *s.last().unwrap() as char;
    if !c.is_alphanumeric() {
        return false;
    }
    s.iter()
        .map(|&b| b as char)
        .all(|c| c.is_alphanumeric() || c == '-')
}

#[cfg(test)]
mod tests {
    #[test]
    fn is_label_valid() {
        let f = |s: &str| super::is_label_valid(s.as_bytes());
        assert!(f("a"));
        assert!(f("alpha"));
        assert!(f("alpha17"));
        assert!(f("alpha-bravo"));
        assert!(f("alpha-bravo17"));
        assert!(!f("-alpha-bravo17"));
        assert!(!f("1alpha"));
        assert!(!f("-alpha"));
        assert!(!f("alpha-"));
        assert!(!f("alpha.bravo"));
    }
}
