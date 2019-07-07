extern crate chrono;

use reader;

#[derive(Debug, PartialEq)]
pub struct ASNInteger<'a> {
    bytes: &'a[u8]
}

impl<'a> ASNInteger<'a> {

    const VALID_I32_LENGTHS : std::ops::Range<usize> = 1usize..4usize;

    pub fn new(bytes: &'a[u8]) -> ASNInteger {
        ASNInteger{bytes}
    }

    fn as_i32(&self) -> Option<i32> {

        // can only parse values with length in [1,4] bytes
        if !ASNInteger::VALID_I32_LENGTHS.contains(&self.bytes.len()) {
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
pub struct ASNBitString<'a> {
    // the number of unused bits in last octet [0, 7]
    unused_bits: u8,
    // the octets, the last one only has (8 - unused_bits) bits
    bytes: &'a[u8]
}

impl<'a> ASNBitString<'a> {
    pub fn new(unused_bits: u8, bytes: &'a[u8]) -> ASNBitString<'a> {
        ASNBitString{ unused_bits, bytes}
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
pub struct ASNObjectIdentifier {
    items: Vec<u32>
}

impl ASNObjectIdentifier {
    pub fn new(items: Vec<u32>) -> ASNObjectIdentifier {
        ASNObjectIdentifier {
            items
        }
    }

    pub fn values(&self) -> &[u32] {
        self.items.as_slice()
    }
}

#[derive(Debug, PartialEq)]
pub enum ASNType<'a> {
    Sequence(&'a[u8]),             // the interior data of the sequence
    Set(&'a[u8]),                          // the interior data of the set
    Integer(ASNInteger<'a>),
    PrintableString(&'a str),
    IA5String(&'a str),
    UTF8String(&'a str),
    Null,
    UTCTime(chrono::DateTime<chrono::FixedOffset>),
    BitString(ASNBitString<'a>),
    OctetString(&'a[u8]),
    ObjectIdentifier(ASNObjectIdentifier)
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
            ASNType::ObjectIdentifier(id) => {
                f.write_str("ObjectIdentifier: ")?;

                match id.values().split_last() {
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
    // these errors relate to core DER parsing
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
    BitStringUnusedBitsTooLarge(u8),
    // these errors relate to schemas
    EndOfStream,
    UnexpectedType(ASNType<'a>)
}

impl<'a> std::convert::From<reader::InputError> for ASNError<'a> {
    fn from(_: reader::InputError) -> Self {
        ASNError::EndOfStream
    }
}

impl<'a> std::fmt::Display for ASNError<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            ASNError::EmptySequence => {
                f.write_str("empty sequence")
            }
            ASNError::EmptySet => {
                f.write_str("empty set")
            }
            ASNError::ZeroLengthInteger => {
                f.write_str("zero length integer")
            }
            ASNError::NullWithNonEmptyContents(contents) => {
                f.write_fmt(format_args!("NULL type w/ non-empty contents (length == {})", contents.len()))
            }
            ASNError::NonUniversalType(tag) => {
                f.write_fmt(format_args!("Non-universal type w/ tag: {})", tag))
            }
            ASNError::UnsupportedUniversalType(tag) => {
                f.write_fmt(format_args!("Unsupported universal type w/ tag: {})", tag))
            }
            ASNError::InsufficientBytes(required, actual) => {
                f.write_fmt(format_args!("Insufficient bytes, required: {} present: {}", required, actual.len()))
            }
            ASNError::UnsupportedIndefiniteLength => {
                f.write_str("Encountered indefinite length encoding. Not allowed in DER.")
            }
            ASNError::ReservedLengthValue => {
                f.write_str("Length byte count of 127 is reserved")
            }
            ASNError::UnsupportedLengthByteCount(length) => {
                f.write_fmt(format_args!("Length byte count of {} not supported", length))
            }
            ASNError::BadLengthEncoding(value) => {
                f.write_fmt(format_args!("Length should be encoded as a single byte: {}", value))
            }
            ASNError::BadOidLength => {
                f.write_str("Bad OID length")
            }
            ASNError::BadUTF8(err) => {
                f.write_fmt(format_args!("Bad UTF8 encoding: {}", err))
            }
            ASNError::BadUTCTime(err, str) => {
                f.write_fmt(format_args!("Bad UTC time string ({}): {}", str, err))
            }
            ASNError::BitStringUnusedBitsTooLarge(unused) => {
                f.write_fmt(format_args!("Bit string w/ unused bits outside range [0..7]: {}", unused))
            }
            ASNError::EndOfStream => {
                f.write_str("Consumed all input before parsing required fields")
            }
            ASNError::UnexpectedType(asn) => {
                f.write_fmt(format_args!("Unexpected type: {}", asn))
            }
        }
    }
}

