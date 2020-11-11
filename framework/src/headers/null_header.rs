use super::EndOffset;
use std::fmt;

#[derive(Default)]
#[repr(C, packed)]
pub struct NullHeader;

impl fmt::Display for NullHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "null")
    }
}

impl EndOffset for NullHeader {
    type PreviousHeader = NullHeader;

    #[inline]
    fn offset(&self) -> usize {
        0
    }
    #[inline]
    fn size() -> usize {
        0
    }
    #[inline]
    fn payload_size(&self, hint: usize) -> usize {
        hint
    }

    #[inline]
    fn check_correct(&self, _: &NullHeader) -> bool {
        true
    }
}
