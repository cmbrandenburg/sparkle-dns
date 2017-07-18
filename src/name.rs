/// `Name` represents a domain name.
pub trait Name<'a> {
    type LabelIter: Iterator<Item = &'a [u8]>;

    /// Returns an iterator that yields each label in the domain name.
    ///
    /// If the domain name is fully qualified—i.e., ends with a dot (`.`)—then
    /// the returned iterator yields an empty slice as its last item. Otherwise,
    /// the iterator yields only nonempty slices.
    ///
    fn labels(&'a self) -> Self::LabelIter;
}
