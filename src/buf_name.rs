use {Error, Name};
use name::{NameParser, ParseItem};
use std::cmp::Ordering;
use std::hash::{Hash, Hasher};

/// `BufName` is a domain name that resides within an internally managed buffer.
#[derive(Clone, Debug)]
pub struct BufName {
    // We store the domain name in its on-the-wire form with one important
    // difference. The buffer content does not contain a final 0x00
    // length-prefix byte if the name is partially qualified. This is needed
    // because on-the-wire names are always fully qualified, whereas BufName
    // must support both full and partial qualification.

    // TODO: Use small-buffer optimization.
    buffer: Vec<u8>,
}

impl BufName {
    /// Tries to construct a domain name from its text form.
    ///
    /// # Example
    ///
    /// ```rust
    /// use sparkle::{BufName, Name};
    ///
    /// let n = BufName::parse(b"example.com").unwrap();
    /// assert_eq!(n.labels().collect::<Vec<_>>(),
    ///            vec!["example".as_bytes(), "com".as_bytes()]);
    ///
    /// let n = BufName::parse(b"example.com.").unwrap();
    /// assert_eq!(n.labels().collect::<Vec<_>>(),
    ///            vec!["example".as_bytes(),
    ///                 "com".as_bytes(),
    ///                 "".as_bytes()]);
    ///
    /// assert!(BufName::parse(b"").unwrap_err().is_because_bad_input());
    /// assert!(BufName::parse(b"alpha..bravo").unwrap_err().is_because_bad_input());
    ///
    /// ```
    pub fn parse(s: &[u8]) -> Result<Self, Error> {

        let mut buffer = Vec::new();
        let mut offset = 0;

        for item in NameParser::new(s) {
            match item {
                Err(e) => return Err(e),
                Ok(ParseItem::StartOfLabel) => {
                    offset = buffer.len();
                    buffer.push(0);
                }
                Ok(ParseItem::Chunk(chunk)) => {
                    buffer[offset] += chunk.len() as u8;
                    buffer.extend(chunk);
                }
                Ok(ParseItem::Octet(octet)) => {
                    buffer[offset] += 1;
                    buffer.push(octet);
                }
                Ok(ParseItem::EndOfLabel) => {}
            }
        }

        Ok(BufName { buffer: buffer })
    }
}

impl PartialEq for BufName {
    fn eq(&self, other: &Self) -> bool {
        self.eq_ignore_ascii_case(other)
    }
}

impl Eq for BufName {}

impl PartialOrd for BufName {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for BufName {
    fn cmp(&self, other: &Self) -> Ordering {
        self.cmp_ignore_ascii_case(other)
    }
}

impl Hash for BufName {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.hash_ignore_ascii_case(state)
    }
}

impl<'a> Name<'a> for BufName {
    type LabelIter = LabelIter<'a>;
    fn labels(&'a self) -> Self::LabelIter {
        LabelIter { cursor: &self.buffer }
    }

    fn len(&'a self) -> usize {
        self.buffer.len()
    }
}

#[derive(Clone, Debug)]
pub struct LabelIter<'a> {
    cursor: &'a [u8],
}

impl<'a> Iterator for LabelIter<'a> {
    type Item = &'a [u8];
    fn next(&mut self) -> Option<Self::Item> {
        match self.cursor.first().map(|&x| x) {
            None => None,
            Some(label_length) => {
                let label_length = label_length as usize;
                let label = &self.cursor[1..1 + label_length];
                self.cursor = &self.cursor[1 + label_length..];
                Some(label)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use testing::HashRecorder;

    #[test]
    fn buf_name_parses_partially_qualified_name() {
        let n = BufName::parse(b"alpha.bravo.charlie").unwrap();
        let labels: Vec<_> = n.labels().collect();
        let expected = &[b"alpha".as_ref(), b"bravo".as_ref(), b"charlie".as_ref()];
        assert_eq!(labels, expected);
    }

    #[test]
    fn buf_name_parses_fully_qualified_name() {
        let n = BufName::parse(b"alpha.bravo.charlie.").unwrap();
        let labels: Vec<_> = n.labels().collect();
        let expected = &[
            b"alpha".as_ref(),
            b"bravo".as_ref(),
            b"charlie".as_ref(),
            b"".as_ref(),
        ];
        assert_eq!(labels, expected);
    }

    #[test]
    fn buf_name_returns_length_for_partially_qualified_name() {
        let n = BufName::parse(b"alpha.bravo.charlie").unwrap();
        assert_eq!(n.len(), 20);
    }

    #[test]
    fn buf_name_returns_length_for_fully_qualified_name() {
        let n = BufName::parse(b"alpha.bravo.charlie.").unwrap();
        assert_eq!(n.len(), 21);
    }

    #[test]
    fn buf_name_equality_is_ascii_case_insensitive() {
        let n1 = BufName::parse(b"alpha.bravo.charlie").unwrap();
        let n2 = BufName::parse(b"ALPHA.BRAVO.CHARLIE").unwrap();
        assert_eq!(n1, n2);
        let n2 = BufName::parse(b"delta.echo.foxtrot").unwrap();
        assert_ne!(n1, n2);
    }

    #[test]
    fn buf_name_implements_eq() {
        fn f<T: Eq>() {}
        f::<BufName>();
    }

    #[test]
    fn buf_name_comparison_is_ascii_case_insensitive() {
        let n1 = BufName::parse(b"alpha.bravo.charlie").unwrap();
        let n2 = BufName::parse(b"DELTA.ECHO.FOXTROT").unwrap();
        assert!(n1 < n2);
        let n3 = BufName::parse(b"golf.hotel.lima").unwrap();
        assert!(n2 < n3);
    }

    #[test]
    fn buf_name_hashing_is_ascii_case_insensitive() {
        let mut h1 = HashRecorder::new();
        BufName::parse(b"alpha.bravo.charlie").unwrap().hash(
            &mut h1,
        );
        let mut h2 = HashRecorder::new();
        BufName::parse(b"ALPHA.BRAVO.CHARLIE").unwrap().hash(
            &mut h2,
        );
        assert_eq!(h1, h2);
        let mut h3 = HashRecorder::new();
        BufName::parse(b"delta.echo.foxtrot").unwrap().hash(&mut h3);
        assert_ne!(h1, h3);
    }

    // TODO: Test Display implementation when zone file parsing is available.
}
