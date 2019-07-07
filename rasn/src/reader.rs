

pub struct Reader<'a> {
    bytes : &'a [u8]
}

#[derive(Debug)]
pub enum InputError {
    EndOfStream
}

impl<'a> Reader<'a> {

    pub fn new(bytes : &'a [u8]) -> Reader {
        Reader{ bytes }
    }

    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    pub fn read_byte(&mut self) -> Result<u8, InputError> {
        if self.bytes.is_empty() {
            Err(InputError::EndOfStream)
        }
        else {
            let value: u8 = self.bytes[0];
            self.bytes = &self.bytes[1..];
            Ok(value)
        }
    }

    pub fn take(&mut self, count: usize) -> Result<&'a [u8], InputError> {
        if self.bytes.len() < count {
            Err(InputError::EndOfStream)
        }
        else {
            let ret = &self.bytes[0..count];
            self.bytes = &self.bytes[count..];
            Ok(ret)
        }
    }

    pub fn remainder(&self) -> &'a [u8] {
        self.bytes
    }
}

#[cfg(test)]
mod tests {
    use reader::*;

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