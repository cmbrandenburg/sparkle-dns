use {Error, ErrorKind, Format, Name, format, std};
use format::MAX_NAME_LENGTH;

#[derive(Debug, Eq, PartialEq)]
pub struct TextFormat;

impl<'a> Format<'a> for TextFormat {
    type Name = TextName;
    type RawOctets = Vec<u8>;
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct TextName {
    inner: String,
}

impl TextName {
    pub fn parse_bytes<S>(s: S) -> Result<Self, Error>
        where S: AsRef<[u8]>
    {
        let s = s.as_ref();

        let len_without_trailing_dot = s.len() - if s.ends_with(b".") { 1 } else { 0 };

        if s.is_empty() {
            return Err(make_text_name_parse_error());
        }

        // "What is the real maximum length of a DNS name?"
        // (https://blogs.msdn.microsoft.com/oldnewthing/20120412-00/?p=7873/)

        if 253 < len_without_trailing_dot {
            return Err(make_text_name_parse_error());
        }

        let mut seen_empty = false;

        for label in s.split(|b| *b == b'.') {
            if seen_empty {
                return Err(make_text_name_parse_error());
            }
            if label.is_empty() {
                seen_empty = true;
            } else if !format::is_hostname_valid(label) {
                return Err(make_text_name_parse_error());
            }
        }

        debug_assert!(std::str::from_utf8(s).is_ok());
        let s = unsafe { std::str::from_utf8_unchecked(s) };

        Ok(TextName { inner: String::from(s) })
    }
}

impl<'a> Name<'a> for TextName {
    type LabelIter = TextLabelIter<'a>;
    fn labels(&'a self) -> Self::LabelIter {
        TextLabelIter { remaining: Some(&self.inner) }
    }
}

impl std::fmt::Display for TextName {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> Result<(), std::fmt::Error> {
        self.inner.fmt(f)
    }
}

impl std::str::FromStr for TextName {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        TextName::parse_bytes(s.as_bytes())
    }
}

#[derive(Clone, Debug)]
pub struct TextLabelIter<'a> {
    remaining: Option<&'a str>,
}

impl<'a> Iterator for TextLabelIter<'a> {
    type Item = &'a str;
    fn next(&mut self) -> Option<Self::Item> {
        match self.remaining {
            None => None,
            Some(s) => {
                let mut split = s.splitn(2, '.');
                let item = split.next();
                debug_assert!(item.is_some());
                self.remaining = split.next();
                item
            }
        }
    }
}

fn make_text_name_parse_error() -> Error {
    Error::new_with_static_message(ErrorKind::BadName, "Invalid DNS name")
}

#[cfg(test)]
mod tests {
    use super::*;
    use ErrorKind;
    use std::str::FromStr;

    #[test]
    fn text_name_from_str() {

        macro_rules! ok {
            ($source:expr) => {
                match TextName::from_str(&$source) {
                    Ok(ref got) if *got == TextName { inner: String::from($source) } => {}
                    got @ _ => panic!("Got unexpected result: {:?}", got),
                }
            }
        }

        macro_rules! nok {
            ($source:expr) => {
                match TextName::from_str(&$source) {
                    Err(ref e) if e.kind() == ErrorKind::BadName => {}
                    got @ _ => panic!("Got unexpected result: {:?}", got),
                }
            }
        }

        ok!("com");
        ok!("com.");
        ok!("example.com");
        ok!("example.com.");

        nok!("");
        nok!(".example.com");
        nok!("example..com");
        nok!("example.com..");
        nok!("-bad-hostname");

        fn make_name(length: usize, trailing_dot: bool) -> String {
            debug_assert!(1 <= length || !trailing_dot);
            let length_without_trailing_dot = length - if trailing_dot { 1 } else { 0 };
            let mut s = String::new();
            for _ in 0..((length_without_trailing_dot - 1) / 2) {
                s.push('x');
                s.push('.');
            }
            let remainder = 2 - (length_without_trailing_dot % 2);
            for _ in 0..remainder {
                s.push('x');
            }
            if trailing_dot {
                s.push('.');
            }
            debug_assert_eq!(s.len(), length);
            s
        }

        // Check that we conform with RFC 1035.
        assert_eq!(MAX_NAME_LENGTH, 255);

        ok!(make_name(MAX_NAME_LENGTH - 2, false));
        ok!(make_name(MAX_NAME_LENGTH - 1, true));
        nok!(make_name(MAX_NAME_LENGTH - 1, false));
        nok!(make_name(MAX_NAME_LENGTH, true));
    }

    #[test]
    fn text_name_labels() {

        let n = TextName::from_str("example.com").unwrap();
        let expected = vec!["example", "com"];
        let got = n.labels().collect::<Vec<_>>();
        assert_eq!(got, expected);

        let n = TextName::from_str("example.com.").unwrap();
        let expected = vec!["example", "com", ""];
        let got = n.labels().collect::<Vec<_>>();
        assert_eq!(got, expected);
    }
}
