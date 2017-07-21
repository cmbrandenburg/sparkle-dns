#[cfg(test)]
pub use self::test_utils::HashRecorder;

#[cfg(test)]
mod test_utils {
    use std::hash::Hasher;

    #[derive(Debug, Eq, PartialEq)]
    pub struct HashRecorder(Vec<u8>);

    impl HashRecorder {
        pub fn new() -> Self {
            HashRecorder(Vec::new())
        }
    }

    impl Hasher for HashRecorder {
        fn finish(&self) -> u64 {
            panic!("HashRecorder does not produce hash values");
        }

        fn write(&mut self, bytes: &[u8]) {
            self.0.extend(bytes)
        }
    }
}
