use std;

#[derive(Debug)]
pub struct Error {
    kind: ErrorKind,
    payload: ErrorPayload,
}

#[derive(Debug)]
enum ErrorPayload {
    Recursive(Box<std::error::Error>),
    DynamicMessage(String),
    StaticMessage(&'static str),
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ErrorKind {
    BadName,
    #[doc(hidden)]
    Other,
}

impl Error {
    pub fn new_with_dynamic_message<M: Into<String>>(kind: ErrorKind, message: M) -> Self {
        Error {
            kind: kind,
            payload: ErrorPayload::DynamicMessage(message.into()),
        }
    }

    pub fn new_with_static_message(kind: ErrorKind, message: &'static str) -> Self {
        Error {
            kind: kind,
            payload: ErrorPayload::StaticMessage(message),
        }
    }

    pub fn new_with_inner_error<E: Into<Box<std::error::Error>>>(kind: ErrorKind, inner_error: E) -> Self {
        Error {
            kind: kind,
            payload: ErrorPayload::Recursive(inner_error.into()),
        }
    }

    pub fn kind(&self) -> ErrorKind {
        self.kind
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> Result<(), std::fmt::Error> {
        match self.payload {
            ErrorPayload::Recursive(ref e) => e.fmt(f),
            ErrorPayload::DynamicMessage(ref m) => m.fmt(f),
            ErrorPayload::StaticMessage(m) => m.fmt(f),
        }
    }
}

impl std::error::Error for Error {
    fn description(&self) -> &str {
        match self.payload {
            ErrorPayload::Recursive(ref e) => e.description(),
            ErrorPayload::DynamicMessage(ref m) => &m,
            ErrorPayload::StaticMessage(m) => m,
        }
    }

    fn cause(&self) -> Option<&std::error::Error> {
        use std::ops::Deref;
        match self.payload {
            ErrorPayload::Recursive(ref e) => Some(e.deref()),
            _ => None,
        }
    }
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::new_with_inner_error(ErrorKind::Other, e)
    }
}
