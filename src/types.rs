extern crate chrono;

#[derive(Debug, PartialEq)]
pub struct IntegerCell<'a> {
    bytes: &'a[u8]
}

impl<'a> IntegerCell<'a> {

    pub fn new(bytes: &'a[u8]) -> IntegerCell {
        IntegerCell{bytes}
    }

    fn as_i32(&self) -> Option<i32> {

        // can only parse values with length in [1,4] bytes
        if !(1usize..4usize).contains(&self.bytes.len()) {
            return None;
        }

        let mut acc : i32 = 0;
        for byte in self.bytes {
            acc <<= 8;
            acc |= *byte as i32;
        }
        Some(acc)
    }
}

#[derive(Debug, PartialEq)]
pub struct BitStringCell<'a> {
    // the number of unused bits in last octet [0, 7]
    unused_bits: u8,
    // the octets, the last one only has (8 - unused_bits) bits
    bytes: &'a[u8]
}

impl<'a> BitStringCell<'a> {
    pub fn new(unused_bits: u8, bytes: &'a[u8]) -> BitStringCell<'a> {
        BitStringCell{ unused_bits, bytes}
    }

    // convertible to octets if it's all full bytes
    pub fn octets(&self) -> Option<&[u8]> {
        if self.unused_bits == 0 {
            Some(self.bytes)
        }
        else {
            None
        }
    }
}

#[derive(Debug, PartialEq)]
pub enum ASNType<'a> {
    Sequence(&'a[u8]),             // the interior data of the sequence
    Set(&'a[u8]),                  // the interior data of the set
    Integer(IntegerCell<'a>),
    PrintableString(&'a str),
    IA5String(&'a str),
    UTF8String(&'a str),
    Null,
    UTCTime(chrono::DateTime<chrono::FixedOffset>),
    BitString(BitStringCell<'a>),
    OctetString(&'a[u8]),
    ObjectIdentifier(Vec<u32>)
}

impl<'a> std::fmt::Display for ASNType<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            ASNType::Sequence(_) => {
                f.write_str("Sequence")
            }
            ASNType::Set(_) => {
                f.write_str("Set")
            },
            ASNType::UTF8String(s) => {
                f.write_str("UTF8String: ")?;
                f.write_str(s)
            },
            ASNType::PrintableString(s) => {
                f.write_str("PrintableString: ")?;
                f.write_str(s)
            },
            ASNType::IA5String(s) => {
                f.write_str("IA5String: ")?;
                f.write_str(s)
            },
            ASNType::Integer(cell) => match cell.as_i32() {
                Some(x) => {
                    f.write_fmt(format_args!("Integer: {}", x))
                },
                None => {
                    f.write_str("Integer: (> u32)")
                }
            }
            ASNType::Null => {
                f.write_str("Null")
            },
            ASNType::ObjectIdentifier(items) => {
                f.write_str("ObjectIdentifier: ")?;

                match items.split_last() {
                    Some((last, first)) => {
                        for value in first {
                            f.write_fmt(format_args!("{}.", value))?;
                        }
                        f.write_fmt(format_args!("{}", last))
                    }
                    None => {
                        Ok(())
                    }
                }

            }
            ASNType::UTCTime(value) => {
                f.write_fmt(format_args!("UTCTime: {}", value))
            }
            ASNType::BitString(_) => {
                f.write_fmt(format_args!("BitString"))
            }
            ASNType::OctetString(_) => {
                f.write_fmt(format_args!("OctetString"))
            }
        }

    }
}


#[derive(Debug, PartialEq)]
pub enum ASNError<'a> {
    EmptySequence,
    EmptySet,
    ZeroLengthInteger,
    NullWithNonEmptyContents(&'a[u8]),
    NonUniversalType(u8),
    UnsupportedUniversalType(u8),
    InsufficientBytes(usize, &'a[u8]),   // the required length and the actual remaining bytes
    UnsupportedIndefiniteLength,
    ReservedLengthValue,
    UnsupportedLengthByteCount(u8),
    BadLengthEncoding(u8),
    BadOidLength,
    BadUTF8(std::str::Utf8Error),
    BadUTCTime(chrono::format::ParseError, &'a str),
    BitStringUnusedBitsTooLarge(u8)
}

