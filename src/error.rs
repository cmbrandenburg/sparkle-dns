use std;
use std::borrow::Cow;

/// `Error` contains information about an error.
#[derive(Debug)]
pub struct Error {
    reason: Cow<'static, str>,
    cause: Option<Box<std::error::Error>>,
    tagged_as_bad_input: bool,
}

#[derive(Debug)]
pub struct ErrorBuilder {
    inner: Error,
}

impl Error {
    #[doc(hidden)]
    pub fn new<R: Into<Cow<'static, str>>>(reason: R) -> ErrorBuilder {
        ErrorBuilder {
            inner: Error {
                reason: reason.into(),
                cause: None,
                tagged_as_bad_input: false,
            },
        }
    }

    /// Returns whether the cause of the error is invalid input.
    pub fn is_because_bad_input(&self) -> bool {
        self.tagged_as_bad_input
    }
}

impl ErrorBuilder {
    pub fn with_cause<E: Into<Box<std::error::Error>>>(mut self, e: E) -> Self {
        self.inner.cause = Some(e.into());
        self
    }

    pub fn tag_as_bad_input(mut self) -> Self {
        self.inner.tagged_as_bad_input = true;
        self
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> Result<(), std::fmt::Error> {
        match self.cause {
            Some(ref cause) => write!(f, "{}: {}", self.reason, cause),
            None => self.reason.fmt(f),
        }
    }
}

impl std::error::Error for Error {
    fn description(&self) -> &str {
        use std::ops::Deref;
        self.reason.deref()
    }

    fn cause(&self) -> Option<&std::error::Error> {
        use std::ops::Deref;
        match self.cause {
            Some(ref e) => Some(e.deref()),
            None => None,
        }
    }
}

#[doc(hidden)]
impl From<ErrorBuilder> for Error {
    fn from(x: ErrorBuilder) -> Self {
        x.inner
    }
}

/*
// We implement From<'static str> and From<String> separately so that we don't
// conflict with From<std::io::Error>.

impl From<&'static str> for Error {
    fn from(reason: &'static str) -> Error {
        Error {
            kind: ErrorKind::Unspecified,
            reason: Cow::Borrowed(reason),
            cause: None,
        }
    }
}

impl From<String> for Error {
    fn from(reason: String) -> Error {
        Error {
            kind: ErrorKind::Unspecified,
            reason: Cow::Owned(reason),
            cause: None,
        }
    }
}

impl<R> From<(ErrorKind, R)> for Error
    where R: Into<Cow<'static, str>>
{
    fn from((kind, reason): (ErrorKind, R)) -> Error {
        Error {
            kind: kind,
            reason: reason.into(),
            cause: None,
        }
    }
}

impl<E, R> From<(R, E)> for Error
    where E: Into<Box<std::error::Error>>,
          R: Into<Cow<'static, str>>
{
    fn from((reason, cause): (R, E)) -> Error {
        Error {
            kind: ErrorKind::Unspecified,
            reason: reason.into(),
            cause: Some(cause.into()),
        }
    }
}

impl<E, R> From<(ErrorKind, R, E)> for Error
    where E: Into<Box<std::error::Error>>,
          R: Into<Cow<'static, str>>
{
    fn from((kind, reason, cause): (ErrorKind, R, E)) -> Error {
        Error {
            kind: kind,
            reason: reason.into(),
            cause: Some(cause.into()),
        }
    }
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error {
            kind: ErrorKind::Unspecified,
            reason: Cow::Borrowed("An I/O error occurred"),
            cause: Some(Box::new(e)),
        }
    }
}
*/
