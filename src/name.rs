/// Encapsulates a domain name.
pub trait Name<'a> {
    type Label: AsRef<[u8]>;
    type LabelIter: Iterator<Item = Self::Label>;

    /// Returns an iterator that yields each label in the name as a separate
    /// string.
    ///
    /// If the name is fully qualified, then the iterator yields the empty
    /// string as its last item. Otherwise, the iterator yields only nonempty
    /// strings.
    ///
    fn labels(&'a self) -> Self::LabelIter;
}
