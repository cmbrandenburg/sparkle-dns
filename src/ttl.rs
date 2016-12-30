use std;

/// Encapsulates a TTL (time-to-live) value.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Ttl(pub u32);

impl Ttl {
    pub fn as_u32(&self) -> u32 {
        self.0
    }
}

impl std::fmt::Display for Ttl {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> Result<(), std::fmt::Error> {
        self.0.fmt(f)
    }
}

impl From<Ttl> for u32 {
    fn from(x: Ttl) -> Self {
        x.0
    }
}
