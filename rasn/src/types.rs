extern crate chrono;

use reader;
use oid::get_oid;

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

// An identifier for the type that carries no data
// used for error purposes
#[derive(Debug, PartialEq)]
pub enum ASNTypeId {
    Sequence,
    Set,
    Integer,
    PrintableString,
    IA5String,
    UTF8String,
    Null,
    UTCTime,
    BitString,
    OctetString,
    ObjectIdentifier
}

impl<'a> ASNType<'a> {
    pub fn get_id(&self) -> ASNTypeId {
        match self {
            ASNType::Sequence(_) => ASNTypeId::Sequence,
            ASNType::Set(_) => ASNTypeId::Set,
            ASNType::Integer(_) => ASNTypeId::Integer,
            ASNType::PrintableString(_) => ASNTypeId::PrintableString,
            ASNType::IA5String(_) => ASNTypeId::IA5String,
            ASNType::UTF8String(_) => ASNTypeId::UTF8String,
            ASNType::Null => ASNTypeId::Null,
            ASNType::UTCTime(_) => ASNTypeId::UTCTime,
            ASNType::BitString(_) => ASNTypeId::BitString,
            ASNType::OctetString(_) => ASNTypeId::OctetString,
            ASNType::ObjectIdentifier(_) => ASNTypeId::ObjectIdentifier
        }
    }
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
                        f.write_fmt(format_args!("{}", last));
                    }
                    None => {}
                }

                if let Some(oid) = get_oid(id) {
                    f.write_fmt(format_args!(" ({})", oid.to_str()));
                }

                Ok(())

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
pub enum ASNError {
    // these errors relate to core DER parsing
    EmptySequence,
    EmptySet,
    EndOfStream,
    ZeroLengthInteger,
    NullWithNonEmptyContents(usize),
    NonUniversalType(u8),
    UnsupportedUniversalType(u8),
    UnsupportedIndefiniteLength,
    ReservedLengthValue,
    UnsupportedLengthByteCount(usize),
    BadLengthEncoding(usize),
    BadOidLength,
    BadUTF8(std::str::Utf8Error),
    BadUTCTime(chrono::format::ParseError),
    BitStringUnusedBitsTooLarge(u8),
    // these errors relate to schemas
    UnexpectedType(ASNTypeId, ASNTypeId),  // the expected type followed by the actual type
    ExpectedEnd(ASNTypeId)                 // type present instead of end
}

impl std::convert::From<reader::EndOfStream> for ASNError {
    fn from(_: reader::EndOfStream) -> Self {
        ASNError::EndOfStream
    }
}

impl std::convert::From<std::str::Utf8Error> for ASNError {
    fn from(err: std::str::Utf8Error) -> Self {
        ASNError::BadUTF8(err)
    }
}

impl std::fmt::Display for ASNError {
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
            ASNError::NullWithNonEmptyContents(length) => {
                f.write_fmt(format_args!("NULL type w/ non-empty contents (length == {})", length))
            }
            ASNError::NonUniversalType(tag) => {
                f.write_fmt(format_args!("Non-universal type w/ tag: {})", tag))
            }
            ASNError::UnsupportedUniversalType(tag) => {
                f.write_fmt(format_args!("Unsupported universal type w/ tag: {})", tag))
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
            ASNError::BadUTCTime(err) => {
                f.write_fmt(format_args!("Bad UTC time string: {}", err))
            }
            ASNError::BitStringUnusedBitsTooLarge(unused) => {
                f.write_fmt(format_args!("Bit string w/ unused bits outside range [0..7]: {}", unused))
            }
            ASNError::EndOfStream => {
                f.write_str("Consumed all input before parsing required fields")
            }
            ASNError::UnexpectedType(expected, actual) => {
                f.write_fmt(format_args!("Expected {:?}, but type is {:?}", expected, actual))
            }
            ASNError::ExpectedEnd(actual) => {
                f.write_fmt(format_args!("Expected end of stream but type is {:?}", actual))
            }
        }
    }
}

