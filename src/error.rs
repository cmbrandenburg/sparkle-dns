use std;
use std::borrow::Cow;

/// `ErrorKind` specifies a high-level error category.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ErrorKind {
    /// The input is invalid.
    InvalidInput,

    #[doc(hidden)]
    Unspecified,
}

/// `Error` stores all information pertaining to an error.
#[derive(Debug)]
pub struct Error {
    kind: ErrorKind,
    reason: Option<Cow<'static, str>>,
    cause: Option<Box<std::error::Error>>,
}

impl Error {
    pub fn new<R>(kind: ErrorKind, reason: R) -> Self
        where R: Into<Cow<'static, str>>
    {
        Error {
            kind: kind,
            reason: Some(reason.into()),
            cause: None,
        }
    }

    pub fn new_with_cause<E, R>(kind: ErrorKind, reason: R, cause: E) -> Self
        where E: Into<Box<std::error::Error>>,
              R: Into<Cow<'static, str>>
    {
        Error {
            kind: kind,
            reason: Some(reason.into()),
            cause: Some(cause.into()),
        }
    }

    pub fn kind(&self) -> ErrorKind {
        self.kind
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> Result<(), std::fmt::Error> {
        match (&self.reason, &self.cause) {
            (&Some(ref reason), &Some(ref cause)) => write!(f, "{}: {}", reason, cause),
            (&Some(ref reason), &None) => reason.fmt(f),
            (&None, &Some(ref cause)) => cause.fmt(f),
            (&None, &None) => unreachable!(),
        }
    }
}

impl std::error::Error for Error {
    fn description(&self) -> &str {
        use std::ops::Deref;
        match (&self.reason, &self.cause) {
            (&Some(ref reason), _) => reason.deref(),
            (_, &Some(ref cause)) => cause.description(),
            (&None, &None) => unreachable!(),
        }
    }

    fn cause(&self) -> Option<&std::error::Error> {
        use std::ops::Deref;
        match self.cause {
            Some(ref e) => Some(e.deref()),
            None => None,
        }
    }
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error {
            kind: ErrorKind::Unspecified,
            reason: None,
            cause: Some(Box::new(e)),
        }
    }
}
