/// Panic-free cursor-like type for reading bytes and slices
#[derive(Copy, Clone, Debug)]
pub struct Reader<'a> {
    bytes: &'a [u8],
}

/// Reached the end of the stream before reading the expected type
#[derive(Copy, Clone, Debug)]
pub struct EndOfStream;

impl core::fmt::Display for EndOfStream {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("end of stream")
    }
}

impl std::error::Error for EndOfStream {}

impl<'a> Reader<'a> {
    pub fn new(bytes: &'a [u8]) -> Self {
        Self { bytes }
    }

    pub fn clear(&mut self) {
        self.bytes = &[];
    }

    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    pub fn peek_byte(&self) -> Result<u8, EndOfStream> {
        match self.bytes.first() {
            None => Err(EndOfStream),
            Some(x) => Ok(*x),
        }
    }

    pub fn read_byte(&mut self) -> Result<u8, EndOfStream> {
        let (first, remainder) = self.bytes.split_first().ok_or(EndOfStream)?;
        self.bytes = remainder;
        Ok(*first)
    }

    pub fn take(&mut self, count: usize) -> Result<&'a [u8], EndOfStream> {
        let ret = self.bytes.get(0..count).ok_or(EndOfStream)?;
        let remainder = self.bytes.get(count..).ok_or(EndOfStream)?;
        self.bytes = remainder;
        Ok(ret)
    }

    pub fn remainder(&self) -> &'a [u8] {
        self.bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_length_on_empty_bytes_fails() {
        let mut input = Reader::new(&[]);
        assert!(input.read_byte().is_err())
    }

    #[test]
    fn consume_advances_the_input() {
        let mut input = Reader::new(&[0xCA, 0xFE]);
        assert_eq!(input.read_byte().unwrap(), 0xCA);
        assert_eq!(input.len(), 1);
        assert_eq!(input.remainder(), [0xFE]);
    }

    #[test]
    fn take_advances_the_input() {
        let mut input = Reader::new(&[0x01, 0x02, 0x03, 0x04]);

        let taken = input.take(3).unwrap();
        assert_eq!(input.len(), 1);
        assert_eq!(input.remainder(), &[0x04]);
        assert_eq!(taken.len(), 3);
        assert_eq!(taken, &[0x01, 0x02, 0x03]);
    }
}
