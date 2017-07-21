use {Error, std};
use std::ascii::AsciiExt;
use std::cmp::Ordering;
use std::fmt::{Display, Formatter};
use std::hash::Hasher;

/// `Name` is a domain name.
///
/// Any type that implements `Name` must implement `Hash`, `Ord`, `PartialEq`,
/// and `PartialOrd` such that the comparison ignores ASCII case. `Name`
/// provides several methods to perform the case-insensitive comparison.
///
pub trait Name<'a> {
    type LabelIter: Iterator<Item = &'a [u8]>;

    /// Returns an iterator that yields each label in the domain name.
    ///
    /// If the domain name is fully qualified—i.e., ends with a dot (`.`)—then
    /// the returned iterator yields an empty slice as its last item. Otherwise,
    /// the iterator yields only nonempty slices.
    ///
    fn labels(&'a self) -> Self::LabelIter;

    /// Returns the number of octets this domain name would use in its
    /// uncompressed, on-the-wire representation.
    ///
    /// On-the-wire domain names are always fully qualified, so there's some
    /// arbitrariness in defining length for partially qualified domain names.
    /// For those cases, we define the length as _not_ including the length of
    /// the root zone name. This has the benefit that when a partially qualified
    /// name is joined with a fully qualified name, the length of the output is
    /// the sum of the lengths of the inputs.
    ///
    /// According to RFC 1035, a domain name has a maximum length of 255 octets.
    ///
    fn len(&'a self) -> usize {
        self.labels().fold(0, |len, label| len + 1 + label.len())
    }

    /// Tests whether the domain name is fully qualified.
    ///
    /// The provided method definition iterates through all labels and checks
    /// whether the final label is empty.
    ///
    fn is_fully_qualified(&'a self) -> bool {
        self.labels().fold(false, |_, label| label.is_empty())
    }

    /// Tests whether the domain name is equal to another when ignoring ASCII
    /// case.
    fn eq_ignore_ascii_case<'b, N: Name<'b>>(&'a self, other: &'b N) -> bool {

        let mut a = self.labels();
        let mut b = other.labels();

        loop {
            match (a.next(), b.next()) {
                (None, None) => return true,
                (Some(ref a), Some(ref b)) if a.eq_ignore_ascii_case(b) => {}
                _ => return false,
            }
        }
    }

    /// Compares the domain name to another while ignoring ASCII case.
    ///
    /// The comparison is a lexicographic comparison of labels, in order, from
    /// the first label to the last, where each octet in each label is compared
    /// as an ASCII character ignoring case.
    ///
    fn cmp_ignore_ascii_case<'b, N: Name<'b>>(&'a self, other: &'b N) -> Ordering {

        // Our algorithm is complicated chiefly by two limitations in the Rust
        // standard library:
        //
        // 1. AsciiExt does not provide a cmp_ignore_ascii_case method, which
        //    would help out a lot.
        // 2. We can't just convert the labels to lowercase (or uppercase) and
        //    then do the comparison because that could yield incorrect results
        //    when a name contains a ASCII character that falls between the
        //    uppercase and lowercase letters.
        //
        // So, basically, we do a byte-by-byte comparison and hope that the
        // optimizer cleans it up.

        let mut a = self.labels();
        let mut b = other.labels();

        // TODO: Replace with AsciiExt::is_ascii_alphabetic when that becomes
        // stable.
        fn is_ascii_alphabetic(x: u8) -> bool {
            x.to_ascii_lowercase() != x.to_ascii_uppercase()
        }

        loop {
            match (a.next(), b.next()) {
                (Some(ref a), Some(ref b)) => {
                    let mut a = a.iter();
                    let mut b = b.iter();
                    loop {
                        match (a.next(), b.next()) {
                            (None, None) => break,
                            (Some(a), Some(b)) if is_ascii_alphabetic(*a) && is_ascii_alphabetic(*b) =>
                                match a.to_ascii_lowercase().cmp(&b.to_ascii_lowercase()) {
                                    Ordering::Equal => continue,
                                    x => return x,
                                },
                            (Some(a), Some(b)) => match a.cmp(&b) {
                                Ordering::Equal => continue,
                                x => return x,
                            },
                            (a, b) => return a.cmp(&b),
                        }
                    }
                }
                (a, b) => return a.cmp(&b),
            }
        }
    }

    /// Hashes the domain name while ignoring ASCII case.
    fn hash_ignore_ascii_case<H: Hasher>(&'a self, state: &mut H) {
        for label in self.labels() {
            state.write_usize(label.len());
            for &c in label {
                state.write_u8(c.to_ascii_lowercase());
            }
        }
    }

    fn write_as_text(&'a self, f: &mut Formatter) -> Result<(), std::fmt::Error> {

        let mut first = true;
        for label in self.labels() {
            if !first || label.is_empty() {
                '.'.fmt(f)?;
            }
            first = false;
            for &c in label {
                match c {
                    b'\\' => r#"\\"#.fmt(f)?,
                    b'.' => r#"\."#.fmt(f)?,
                    b' ' => r#"\ "#.fmt(f)?,
                    b'\t' => "\\\t".fmt(f)?,
                    b'"' => r#"\""#.fmt(f)?,
                    b';' => r#"\;"#.fmt(f)?,
                    32...126 => (c as char).fmt(f)?, // i.e., is ASCII printable
                    _ => {
                        '\\'.fmt(f)?;
                        ((b'0' + (c / 100 % 10)) as char).fmt(f)?;
                        ((b'0' + (c / 10 % 10)) as char).fmt(f)?;
                        ((b'0' + (c / 1 % 10)) as char).fmt(f)?
                    }
                }
            }
        }

        Ok(())
    }
}

const E_NAME_IS_EMPTY: &str = "Domain name is invalid (reason: cannot be empty)";
const E_NAME_STARTS_WITH_DOT: &str = "Domain name is invalid (reason: cannot start with dot)";
const E_NAME_HAS_EMPTY_LABEL: &str = "Domain name is invalid (reason: cannot have empty label)";
const E_NAME_LABEL_IS_TOO_LONG: &str = "Domain name is invalid (reason: label cannot exceed 63 octets)";
const E_NAME_IS_TOO_LONG: &str = "Domain name is invalid (reason: name in wire form cannot exceed 255 octets)";
const E_NAME_ENDS_WITH_BACKSLASH: &str = "Domain name is invalid (reason: cannot end with backslash)";

const MAX_LABEL_LENGTH: usize = 63;
const MAX_NAME_LENGTH: usize = 255;

// NameParser parses a domain name in text form (e.g, "example.com") into its
// constituent labels (e.g., ["example", "com"]). NameParser neither allocates
// nor copies memory.
//
// NameParser returns labels via **chunks**, which are contiguous regions of
// memory. Chunks are a workaround for how some domain names in text form use
// escape sequences (e.g., "\ " and "\032") to encode special characters.
// Because the backslash is not part of the label data, NameParser skips over it
// by returning the chunk of data before the backslash and the chunk after. The
// caller would then stitch the two chunks together to form the complete
// label--or stitch together more than two chunks, if the label contains two or
// more escape sequences.
//
// Decimal escape sequences (e.g., "\032") are even more special, as the escaped
// octet does not exist in the text form and thus can't be returned as part of a
// chunk. For these cases, NameParser returns the octet by itself, not as part
// of a chunk.
//
#[derive(Debug)]
pub struct NameParser<'a> {
    cursor: &'a [u8],
    name_length: usize,
    state: ParseState,
}

#[derive(Debug)]
pub enum ParseItem<'a> {
    StartOfLabel,
    Chunk(&'a [u8]),
    Octet(u8),
    EndOfLabel,
}

#[derive(Clone, Copy, Debug)]
enum ParseState {
    Init,
    Done,
    StartOfLabel,
    InLabel { escaped: bool, label_length: usize },
}

impl<'a> NameParser<'a> {
    pub fn new(s: &'a [u8]) -> Self {
        NameParser {
            cursor: s,
            name_length: 0,
            state: ParseState::Init,
        }
    }
}

impl<'a> Iterator for NameParser<'a> {
    type Item = Result<ParseItem<'a>, Error>;
    fn next(&mut self) -> Option<Self::Item> {

        fn make_error<'a>(p: &mut NameParser<'a>, reason: &'static str) -> Option<Result<ParseItem<'a>, Error>> {
            p.state = ParseState::Done;
            Some(Err(Error::new(reason).tag_as_bad_input().into()))
        }

        fn starts_with_octet_decimal(s: &[u8]) -> Option<u8> {

            if s.len() < 3 {
                return None;
            }

            let mut sum = 0;

            for &c in s.iter().take(3) {
                if c < b'0' || b'9' < c {
                    return None;
                }
                sum *= 10;
                sum += (c - b'0') as u16;
            }

            if sum <= 0xff { Some(sum as u8) } else { None }
        }

        loop {
            match self.state {
                ParseState::Init => {
                    if self.cursor.is_empty() {
                        return make_error(self, E_NAME_IS_EMPTY);
                    }
                    if self.cursor != b"." && self.cursor.starts_with(b".") {
                        return make_error(self, E_NAME_STARTS_WITH_DOT);
                    }
                    if self.cursor == b"." {
                        self.cursor = &self.cursor[1..];
                    }
                    self.state = ParseState::StartOfLabel;
                }
                ParseState::Done => return None,
                ParseState::StartOfLabel => {
                    self.name_length += 1;
                    if MAX_NAME_LENGTH < self.name_length {
                        return make_error(self, E_NAME_IS_TOO_LONG);
                    }
                    self.state = ParseState::InLabel {
                        escaped: false,
                        label_length: 0,
                    };
                    return Some(Ok(ParseItem::StartOfLabel));
                }
                ParseState::InLabel {
                    escaped,
                    mut label_length,
                } => {
                    if self.cursor.is_empty() {
                        self.state = ParseState::Done;
                        return Some(Ok(ParseItem::EndOfLabel));
                    }
                    if !escaped && self.cursor.starts_with(b".") {
                        self.cursor = &self.cursor[1..];
                        self.state = ParseState::StartOfLabel;
                        if label_length == 0 {
                            return make_error(self, E_NAME_HAS_EMPTY_LABEL);
                        }
                        return Some(Ok(ParseItem::EndOfLabel));
                    }
                    if !escaped && self.cursor == b"\\" {
                        return make_error(self, E_NAME_ENDS_WITH_BACKSLASH);
                    }
                    let chunk = if !escaped && self.cursor.starts_with(b"\\") {
                        self.cursor = &self.cursor[1..];
                        if let Some(octet) = starts_with_octet_decimal(self.cursor) {
                            self.cursor = &self.cursor[3..];
                            label_length += 1;
                            self.state = ParseState::InLabel {
                                escaped: true,
                                label_length,
                            };
                            return Some(Ok(ParseItem::Octet(octet)));
                        }
                        match self.cursor.iter().enumerate().find(|&(i, &c)| {
                            i != 0 && (c == b'.' || c == b'\\')
                        }) {
                            None => self.cursor,
                            Some((index, _)) => &self.cursor[..index],
                        }
                    } else {
                        match self.cursor.iter().enumerate().find(|&(_, &c)| {
                            c == b'.' || c == b'\\'
                        }) {
                            None => self.cursor,
                            Some((index, _)) => &self.cursor[..index],
                        }
                    };
                    label_length += chunk.len();
                    if MAX_LABEL_LENGTH < label_length {
                        return make_error(self, E_NAME_LABEL_IS_TOO_LONG);
                    }
                    self.name_length += chunk.len();
                    if MAX_NAME_LENGTH < self.name_length {
                        return make_error(self, E_NAME_IS_TOO_LONG);
                    }
                    self.cursor = &self.cursor[chunk.len()..];
                    self.state = ParseState::InLabel {
                        escaped: false,
                        label_length,
                    };
                    return Some(Ok(ParseItem::Chunk(chunk)));
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use std;
    use testing::HashRecorder;

    #[derive(Debug)]
    struct TestName(Vec<&'static [u8]>);

    impl TestName {
        pub fn new(s: &'static str) -> Self {
            assert!(!s.is_empty());
            match s {
                "." => TestName(vec![b""]),
                _ => TestName(s.split('.').map(|x| x.as_bytes()).collect()),
            }
        }
    }

    impl<'a> Name<'a> for TestName {
        type LabelIter = std::iter::Map<std::slice::Iter<'a, &'a [u8]>, fn(&'a &[u8]) -> &'a [u8]>;
        fn labels(&'a self) -> Self::LabelIter {
            fn f<'a>(x: &'a &[u8]) -> &'a [u8] {
                *x
            }
            self.0.iter().map(f as _)
        }
    }

    impl std::fmt::Display for TestName {
        fn fmt(&self, f: &mut std::fmt::Formatter) -> Result<(), std::fmt::Error> {
            self.write_as_text(f)
        }
    }

    #[test]
    fn test_name_constructs_correctly() {
        assert_eq!(TestName::new(".").0, vec![b""]);
        assert_eq!(TestName::new("alpha").0, vec!["alpha".as_bytes()]);
        assert_eq!(
            TestName::new("alpha.").0,
            vec!["alpha".as_bytes(), "".as_bytes()]
        );
        assert_eq!(
            TestName::new("alpha.bravo").0,
            vec!["alpha".as_bytes(), "bravo".as_bytes()]
        );
        assert_eq!(
            TestName::new("alpha.bravo.").0,
            vec!["alpha".as_bytes(), "bravo".as_bytes(), "".as_bytes()]
        );
    }

    #[test]
    fn name_provides_len() {

        macro_rules! tc {
            ($expected:expr, $source:expr) => {
                let n = TestName::new($source);
                assert_eq!(n.len(), $expected);
            };
        }

        tc!(1, ".");
        tc!(6, "alpha");
        tc!(7, "alpha.");
        tc!(12, "alpha.bravo");
        tc!(13, "alpha.bravo.");
        tc!(6, "a.b.c");
        tc!(7, "a.b.c.");
    }

    #[test]
    fn name_provides_is_fully_qualified() {

        macro_rules! tc {
            (y, $source:expr) => {
                let n = TestName::new($source);
                assert!(n.is_fully_qualified());
            };
            (n, $source:expr) => {
                let n = TestName::new($source);
                assert!(!n.is_fully_qualified());
            };
        }

        tc!(y, ".");
        tc!(n, "alpha");
        tc!(y, "alpha.");
        tc!(n, "alpha.bravo");
        tc!(y, "alpha.bravo.");
    }

    #[test]
    fn name_provides_case_insensitive_equality_comparison_and_hashing() {

        macro_rules! tc {
            (eq, $a_source:expr, $b_source:expr) => {
                let a = TestName::new($a_source);
                let b = TestName::new($b_source);
                assert!(a.eq_ignore_ascii_case(&b));
                assert!(b.eq_ignore_ascii_case(&a));
                assert_eq!(a.cmp_ignore_ascii_case(&b), std::cmp::Ordering::Equal);
                assert_eq!(b.cmp_ignore_ascii_case(&a), std::cmp::Ordering::Equal);
                let mut ha = HashRecorder::new();
                a.hash_ignore_ascii_case(&mut ha);
                let mut hb = HashRecorder::new();
                b.hash_ignore_ascii_case(&mut hb);
                assert_eq!(ha, hb);
            };
            (lt, $a_source:expr, $b_source:expr) => {
                let a = TestName::new($a_source);
                let b = TestName::new($b_source);
                assert!(!a.eq_ignore_ascii_case(&b));
                assert!(!b.eq_ignore_ascii_case(&a));
                assert_eq!(a.cmp_ignore_ascii_case(&b), std::cmp::Ordering::Less);
                assert_eq!(b.cmp_ignore_ascii_case(&a), std::cmp::Ordering::Greater);
                let mut ha = HashRecorder::new();
                a.hash_ignore_ascii_case(&mut ha);
                let mut hb = HashRecorder::new();
                b.hash_ignore_ascii_case(&mut hb);
                assert_ne!(ha, hb);
            };
        }

        tc!(eq, ".", ".");
        tc!(eq, "alpha", "alpha");
        tc!(eq, "alpha.", "alpha.");
        tc!(eq, "alpha.bravo", "alpha.bravo");
        tc!(eq, "alpha.bravo.", "alpha.bravo.");
        tc!(eq, "alpha", "ALPHA");
        tc!(eq, "alpha", "aLpHa");

        tc!(lt, ".", "alpha");
        tc!(lt, ".", "alpha.");
        tc!(lt, "alpha", "alpha.");
        tc!(lt, "alpha", "alpha.bravo");
        tc!(lt, "alpha", "alpha.bravo.");
        tc!(lt, "alpha.", "alpha.bravo");
        tc!(lt, "alpha.", "alpha.bravo.");
        tc!(lt, "alpha.bravo", "alpha.bravo.");

        tc!(lt, "alpha.charlie", "bravo.bravo");

        tc!(lt, "alphaalpha", "alphabravo");

        tc!(lt, "alpha", "BRAVO");
        tc!(lt, "ALPHA", "bravo");
        tc!(lt, "alpha.bravo", "bRaVo.AlPhA");

        // The underscore character ('_') is less than lowercase letters but
        // greater than uppercase letters. As such, unequal comparisons should
        // order it as such.
        //
        // Technically, underscore is not allowed in domain names. However,
        // `Name` doesn't enforce domain name validity, so the comparison must
        // account for bad characters.

        tc!(eq, "_alpha", "_alpha");
        tc!(eq, "_alpha", "_ALPHA");
        tc!(lt, "_alpha", "alpha");
        tc!(lt, "ALPHA", "_alpha");
    }

    #[test]
    fn name_provides_write_as_text() {

        fn parse(s: &[u8]) -> Result<Vec<Vec<u8>>, Error> {
            let mut v = Vec::new();
            for item in NameParser::new(s) {
                match item {
                    Err(e) => return Err(e),
                    Ok(ParseItem::StartOfLabel) => {
                        v.push(Vec::new());
                    }
                    Ok(ParseItem::Chunk(chunk)) => {
                        v.last_mut().unwrap().extend(chunk);
                    }
                    Ok(ParseItem::Octet(octet)) => {
                        v.last_mut().unwrap().push(octet);
                    }
                    Ok(ParseItem::EndOfLabel) => {}
                }
            }
            Ok(v)
        }

        macro_rules! tc {
            (ok, $source:expr) => {
                let s = $source.to_string();

                // Verify that parsing the string yields the same labels as the
                // input name.

                let labels = parse(s.as_bytes()).unwrap();
                assert_eq!(labels, $source.0);

                // FIXME: Verify that all special characters are escaped.
            };
        }

        tc!(ok, TestName::new("."));
        tc!(ok, TestName::new("alpha"));
        tc!(ok, TestName::new("alpha."));
        tc!(ok, TestName::new("alpha.bravo"));
        tc!(ok, TestName::new("alpha.bravo."));
        tc!(ok, TestName::new("alpha.bravo.charlie"));

        tc!(ok, TestName(vec![b"alpha bravo".as_ref()]));
        tc!(ok, TestName(vec![b"alpha\tbravo".as_ref()]));
        tc!(ok, TestName(vec![b"alpha\\bravo".as_ref()]));
        tc!(ok, TestName(vec![b"alpha\"bravo".as_ref()]));
        tc!(ok, TestName(vec![b"alpha;bravo".as_ref()]));
    }

    #[test]
    fn name_parser() {

        fn parse(s: &[u8]) -> Result<(bool, Vec<u8>), Error> {
            let mut v = Vec::new();
            let mut offset = 0;
            let mut end_of_label = false;
            for item in NameParser::new(s) {
                match item {
                    Ok(ParseItem::StartOfLabel) => {
                        end_of_label = false;
                        offset = v.len();
                        v.push(0);
                    }
                    Ok(ParseItem::Chunk(chunk)) => {
                        end_of_label = false;
                        v[offset] += chunk.len() as u8;
                        v.extend(chunk);
                    }
                    Ok(ParseItem::Octet(octet)) => {
                        end_of_label = false;
                        v[offset] += 1;
                        v.push(octet);
                    }
                    Ok(ParseItem::EndOfLabel) => {
                        end_of_label = true;
                    }
                    Err(e) => return Err(e),
                }
            }
            Ok((end_of_label, v))
        }

        macro_rules! tc {
            (ok, $expected:expr, $source:expr) => {
                match parse($source) {
                    Ok((true, ref v)) if v == &$expected.as_ref() => {}
                    Ok((ends_of_label, ref v)) => {
                        if !ends_of_label {
                            panic!("Parsing did not yield EndOfLabel as final item");
                        }
                        panic!("Got unexpected result (got: {:?}, expected: {:?})",
                            String::from_utf8_lossy(v).as_ref(),
                            String::from_utf8_lossy($expected).as_ref()
                        );
                    }
                    Err(e) => panic!("Got unexpected error {:?}", e),
                }
            };

            (nok, $expected_err:expr, $source:expr) => {
                match parse($source) {
                    Err(ref e) if e.is_because_bad_input() && e.to_string().contains($expected_err) => {}
                    x => panic!("Got unexpected result {:?}", x),
                }
            };
        }

        tc!(nok, E_NAME_IS_EMPTY, b"");

        tc!(ok, b"\x00", b".");
        tc!(nok, E_NAME_STARTS_WITH_DOT, b".alpha");
        tc!(nok, E_NAME_STARTS_WITH_DOT, b"..");

        tc!(ok, b"\x05alpha", b"alpha");
        tc!(ok, b"\x05alpha\x00", b"alpha.");
        tc!(ok, b"\x05alpha\x05bravo", b"alpha.bravo");
        tc!(ok, b"\x05alpha\x05bravo\x00", b"alpha.bravo.");
        tc!(ok, b"\x05alpha\x05bravo\x07charlie", b"alpha.bravo.charlie");

        tc!(nok, E_NAME_HAS_EMPTY_LABEL, b"alpha..bravo");
        tc!(nok, E_NAME_HAS_EMPTY_LABEL, b"alpha..");
        tc!(nok, E_NAME_HAS_EMPTY_LABEL, b"alpha...bravo");
        tc!(nok, E_NAME_HAS_EMPTY_LABEL, b"alpha..");

        tc!(ok, b"\x0balpha.bravo\x00", b"alpha\\.bravo.");
        tc!(ok, b"\x0balpha\\bravo\x00", b"alpha\\\\bravo.");
        tc!(ok, b"\x05alpha\x01.\x05bravo\x00", b"alpha.\\..bravo.");
        tc!(ok, b"\x05alpha\x00", b"\\alpha.");

        tc!(ok, b"\x05alpha\x00", b"\\097lpha.");
        tc!(ok, b"\x05alpha\x00", b"alph\\097.");
        tc!(ok, b"\x05alpha\x00", b"al\\112ha.");
        tc!(ok, b"\x05alpha\x00", b"\\097\\108\\112\\104\\097.");
        tc!(ok, b"\x0balpha.bravo\x00", b"alpha\\046bravo.");
        tc!(ok, b"\x0balpha\x00bravo\x00", b"alpha\\000bravo.");

        // Spaces and quotes are not special.

        tc!(ok, b"\x0balpha bravo\x00", b"alpha bravo.");
        tc!(ok, b"\x0balpha bravo\x00", b"alpha\\ bravo.");
        tc!(ok, b"\x0balpha bravo\x00", b"alpha\\032bravo.");
        tc!(ok, b"\x0balpha\"bravo\x00", b"alpha\"bravo.");
        tc!(ok, b"\x0balpha\"bravo\x00", b"alpha\\\"bravo.");
        tc!(ok, b"\x0balpha\"bravo\x00", b"alpha\\034bravo.");

        // We liberally accept bad octet decimal values in the input.

        tc!(ok, b"\x0balpha0bravo\x00", b"alpha\\0bravo.");
        tc!(ok, b"\x0calpha00bravo\x00", b"alpha\\00bravo.");
        tc!(ok, b"\x0balpha\xffbravo\x00", b"alpha\\255bravo.");
        tc!(ok, b"\x0dalpha256bravo\x00", b"alpha\\256bravo.");
        tc!(ok, b"\x06alpha0\x00", b"alpha\\0.");
        tc!(ok, b"\x07alpha00\x00", b"alpha\\00.");
        tc!(ok, b"\x06alpha\x00\x00", b"alpha\\000.");
        tc!(ok, b"\x06alpha0", b"alpha\\0");
        tc!(ok, b"\x07alpha00", b"alpha\\00");
        tc!(ok, b"\x06alpha\x00", b"alpha\\000");

        tc!(ok, b"\x06alpha\\", b"alpha\\\\");
        tc!(ok, b"\x06alpha.", b"alpha\\.");
        tc!(nok, E_NAME_ENDS_WITH_BACKSLASH, b"alpha\\");
        tc!(nok, E_NAME_ENDS_WITH_BACKSLASH, b"alpha.\\");
        tc!(nok, E_NAME_ENDS_WITH_BACKSLASH, b"alpha\\\\\\");

        // The following tests are maximum-length checks. In each case, we
        // ensure the max case is successful. Then we add one octet to push the
        // expected result into error.

        tc!(
            ok,
            b"\x3fThe-maximum-length-of-a-domain-name-label-is-sixty-three-octets\
              \x00",
            b"The-maximum-length-of-a-domain-name-label-is-sixty-three-octets."
        );

        tc!(
            nok,
            E_NAME_LABEL_IS_TOO_LONG,
            b"This-label-is-sixty-four-octets-in-length-and-thats-one-too-many."
        );

        tc!(
            ok,
            b"\x3fThe-backslashes-in-a-name-dont-count-against-its-label-length-x\
              \x00",
            b"\\T\\h\\e-backslashes-in-a-name-dont-count-against-its-label-length\\-\\x."
        );

        tc!(
            nok,
            E_NAME_LABEL_IS_TOO_LONG,
            b"\\T\\h\\e-backslashes-in-a-name-dont-count-against-its-label-length\\-\\x\\x."
        );

        tc!(
            ok,
            b"\x3fThe-maximum-length-of-a-domain-name-is-255-octets-xxxx-xxxx-xxx\
              \x3fThat-includes-an-octet-length-prefix-for-each-label-xxxx-xxxx-x\
              \x3fAnd-the-trailing-dot-counts-as-an-empty-label-xxxx-xxxx-xxxx-xx\
              \x3dSo-this-label-is-only-sixty-one-octets-in-length-xxxx-xxxx-xx\
              \x00",
            b"The-maximum-length-of-a-domain-name-is-255-octets-xxxx-xxxx-xxx.\
              That-includes-an-octet-length-prefix-for-each-label-xxxx-xxxx-x.\
              And-the-trailing-dot-counts-as-an-empty-label-xxxx-xxxx-xxxx-xx.\
              So-this-label-is-only-sixty-one-octets-in-length-xxxx-xxxx-xx."
        );

        tc!(
            nok,
            E_NAME_IS_TOO_LONG,
            b"The-maximum-length-of-a-domain-name-is-255-octets-xxxx-xxxx-xxx.\
              That-includes-an-octet-length-prefix-for-each-label-xxxx-xxxx-x.\
              And-the-trailing-dot-counts-as-an-empty-label-xxxx-xxxx-xxxx-xx.\
              So-this-label-being-sixty-two-octets-is-one-too-many-xxxx-xxxx."
        );

        tc!(
            nok,
            E_NAME_IS_TOO_LONG,
            b"\\T\\h\\e-backslashes-in-a-name-dont-count-against-its-name-length-\\x\\x.\
              \\x\\xxx-xxxx-xxxx-xxxx-xxxx-xxxx-xxxx-xxxx-xxxx-xxxx-xxxx-xxxx-x\\x\\x.\
              \\x\\xxx-xxxx-xxxx-xxxx-xxxx-xxxx-xxxx-xxxx-xxxx-xxxx-xxxx-xxxx-x\\x\\x.\
              \\x\\xxx-xxxx-xxxx-xxxx-xxxx-xxxx-xxxx-xxxx-xxxx-xxxx-xxxx-xxxx\\-\\xx."
        );
    }
}
