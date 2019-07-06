

pub struct Input<'a> {
    bytes : &'a [u8],
    pos: usize
}

#[derive(Debug)]
pub enum InputError {
    EndOfStream(usize)
}

impl<'a> Input<'a> {
    pub fn new(bytes : &[u8]) -> Input {
        Input { bytes, pos: 0 }
    }

    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    pub fn iter(&self) -> std::slice::Iter<u8>{
        self.bytes.iter()
    }

    pub fn as_slice_less_safe(&self) -> &[u8] {
        self.bytes
    }

    pub fn consume(&mut self) -> Result<u8, InputError> {
        if self.bytes.is_empty() {
            Err(InputError::EndOfStream(self.pos))
        }
        else {
            self.pos += 1;
            let value: u8 = self.bytes[0];
            self.bytes = &self.bytes[1..];
            Ok(value)
        }
    }

    pub fn take(&mut self, count: usize) -> Result<Input<'a>, InputError> {
        if self.bytes.len() < count {
            Err(InputError::EndOfStream(self.pos))
        }
        else {
            let ret = Input::new(&self.bytes[0..count]);
            self.pos += count;
            self.bytes = &self.bytes[count..];
            Ok(ret)
        }
    }
}

#[cfg(test)]
mod tests {
    use input::*;

    #[test]
    fn decode_length_on_empty_bytes_fails() {
        let mut input = Input::new(&[]);
        assert!(input.consume().is_err())
    }

    #[test]
    fn consume_advances_the_input() {
        let mut input = Input::new(&[0xCA, 0xFE]);
        assert_eq!(input.consume().unwrap(), 0xCA);
        assert_eq!(input.len(), 1);
        assert_eq!(input.as_slice_less_safe(), [0xFE]);
    }

    #[test]
    fn can_iterate_over_underlying_slice() {
        let underlying = [0xCA, 0xFE];

        let input = Input::new(&underlying);

        let mut vec : Vec<u8> = Vec::new();
        for byte in input.iter() {
            vec.push(*byte)
        }

        assert_eq!(&underlying, vec.as_slice())
    }

    #[test]
    fn take_advances_the_input() {
        let mut input = Input::new(&[0x01, 0x02, 0x03, 0x04]);

        let taken = input.take(3).unwrap();
        assert_eq!(input.len(), 1);
        assert_eq!(input.as_slice_less_safe(), &[0x04]);
        assert_eq!(taken.len(), 3);
        assert_eq!(taken.as_slice_less_safe(), &[0x01, 0x02, 0x03]);
    }
}
