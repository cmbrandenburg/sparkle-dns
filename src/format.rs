use {QClass, QType, RClass, RType, Serial, Ttl, std};

pub const MAX_NAME_LENGTH: usize = 255;

/// Associates the set of DNS types for a common format.
pub trait Format<'a> {
    type Name: Name<'a>;
    type RawOctets: AsRef<[u8]> + Clone + std::fmt::Debug + Eq + PartialEq;
}

/// Encapsulates a domain name.
pub trait Name<'a>: std::fmt::Display {
    type LabelIter: Iterator<Item = &'a str>;

    /// Returns an iterator that yields each label in the name as a separate
    /// string.
    ///
    /// If the name is fully qualified, then the iterator yields the empty
    /// string as its last item. Otherwise, the iterator yields only nonempty
    /// strings.
    ///
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
    rtype: RType,
    rclass: RClass,
    ttl: Ttl,
    rdata: RData<'a, F>,
}

impl<'a, F: Format<'a>> ResourceRecord<'a, F> {
    pub fn new<N: Into<F::Name>, IntoT: Into<Ttl>, R: Into<RData<'a, F>>>(name: N,
                                                                          rtype: RType,
                                                                          rclass: RClass,
                                                                          ttl: IntoT,
                                                                          rdata: R)
                                                                          -> Self {
        ResourceRecord {
            name: name.into(),
            rtype: rtype,
            rclass: rclass,
            ttl: ttl.into(),
            rdata: rdata.into(),
        }
    }

    pub fn name(&self) -> &F::Name {
        &self.name
    }

    pub fn rtype(&self) -> RType {
        self.rtype
    }

    pub fn rclass(&self) -> RClass {
        self.rclass
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
        serial: Serial,
        refresh: Ttl,
        retry: Ttl,
        expire: Ttl,
        minimum: Ttl,
    },
    Other { octets: F::RawOctets },
}

pub fn is_hostname_valid(s: &[u8]) -> bool {

    // The root name is the empty string. However, we treat empty hostnames as
    // invalid.

    if s.is_empty() {
        return false;
    }

    if 63 < s.len() {
        return false;
    }

    // A hostname must begin and end with a letter or digit (RFC 1123, section
    // 2.1 "Host Names and Numbers").

    let c = *s.first().unwrap() as char;
    if !c.is_alphanumeric() {
        return false;
    }
    let c = *s.last().unwrap() as char;
    if !c.is_alphanumeric() {
        return false;
    }

    if !s.iter()
            .map(|&b| b as char)
            .all(|c| c.is_alphanumeric() || c == '-') {
        return false;
    }

    // Hostnames are valid UTF-8 because they use only ASCII characters. Callers
    // may assume this. If this assumption is ever relaxed then we'll need to
    // possibly fix the callers, too.

    debug_assert!(std::str::from_utf8(s).is_ok()); // !warning: read comment above!

    true
}

#[cfg(test)]
mod tests {
    #[test]
    fn is_hostname_valid() {

        let f = |s: &str| super::is_hostname_valid(s.as_bytes());

        assert!(f("a"));
        assert!(f("alpha"));
        assert!(f("alpha17"));
        assert!(f("alpha-bravo"));
        assert!(f("alpha-bravo17"));

        assert!(!f(""));
        assert!(f("the-longest-allowed-hostname-is-63-octets-xxxx-xxxx-xxxx-xxxx-x"));
        assert!(!f("the-longest-allowed-hostname-is-63-octets-xxxx-xxxx-xxxx-xxxx-xx"));

        assert!(f("7"));
        assert!(f("17"));
        assert!(f("7alpha"));
        assert!(f("17alpha"));

        assert!(!f("-alpha"));
        assert!(!f("-alpha-bravo"));
        assert!(!f("alpha-"));
        assert!(!f("alpha-bravo-"));
        assert!(!f("-alpha-"));
        assert!(!f("-alpha-bravo-"));

        assert!(!f("alpha.bravo"));
    }
}
