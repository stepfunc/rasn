extern crate chrono;

use reader;
use oid::get_oid;
use std::fmt::Display;

#[derive(Debug, PartialEq)]
pub struct ASNInteger<'a> {
    bytes: &'a[u8]
}

#[derive(Debug, PartialEq)]
pub enum TagClass {
    Universal,
    Application,
    ContextSpecific,
    Private
}

#[derive(Debug, PartialEq)]
pub enum PC {
    Primitive,
    Constructed
}

#[derive(Debug, PartialEq)]
pub struct Identifier {
    pub class : TagClass,
    pub pc : PC,
    pub tag: u8
}

impl Identifier {

    pub fn new(class : TagClass, pc : PC, tag: u8) -> Identifier{
        Identifier { class, pc, tag }
    }

    pub fn from(byte: u8) -> Identifier {

        let class = match byte & 0b11000000 {
            0b00000000 => TagClass::Universal,
            0b01000000 => TagClass::Application,
            0b10000000 => TagClass::ContextSpecific,
            _ => TagClass::Private
        };

        let pc = if (byte & 0b00100000) != 0 {
            PC::Constructed
        } else { PC::Primitive };

        let tag = byte & 0b00011111;

        Identifier::new(class, pc, tag)
    }
}

impl<'a> ASNInteger<'a> {

    const VALID_I32_LENGTHS : std::ops::Range<usize> = 1usize..4usize;

    pub fn new(bytes: &'a[u8]) -> ASNInteger {
        ASNInteger{bytes}
    }

    pub fn as_i32(&self) -> Option<i32> {

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

impl<'a> Display for ASNInteger<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self.as_i32() {
            Some(x) => write!(f, "{}", x),
            None => {
                if let Some((tail, head)) = self.bytes.split_last() {
                    for byte in head {
                        write!(f, "{:02X}:", byte)?;
                    }
                    write!(f, "{:02X}", tail)
                } else {
                    write!(f, "[]")
                }
            }
        }
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

impl Display for ASNObjectIdentifier {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> Result<(), std::fmt::Error> {
        match get_oid(self.values()) {
            Some(oid) => f.write_str(oid.to_str()),
            None => {
                if let Some((last, first)) = self.values().split_last() {
                    for value in first {
                        write!(f, "{}.", value)?;
                    }
                    write!(f, "{}", last)?;
                }
                Ok(())
            }
        }
    }
}

#[derive(Debug, PartialEq)]
pub enum ASNType<'a> {
    Boolean(bool),
    Sequence(&'a[u8]),             // the interior data of the sequence
    Set(&'a[u8]),                  // the interior data of the set
    Integer(ASNInteger<'a>),
    PrintableString(&'a str),
    IA5String(&'a str),
    UTF8String(&'a str),
    Null,
    UTCTime(chrono::DateTime<chrono::FixedOffset>),
    BitString(ASNBitString<'a>),
    OctetString(&'a[u8]),
    ObjectIdentifier(ASNObjectIdentifier),
    ExplicitTag(u8, &'a[u8])       // the tag value and the data
}

// An identifier for the type that carries no data
// used for error purposes
#[derive(Debug, PartialEq)]
pub enum ASNTypeId {
    Boolean,
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
    ObjectIdentifier,
    ExplicitTag
}

impl<'a> ASNType<'a> {
    pub fn get_id(&self) -> ASNTypeId {
        match self {
            ASNType::Boolean(_) => ASNTypeId::Boolean,
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
            ASNType::ObjectIdentifier(_) => ASNTypeId::ObjectIdentifier,
            ASNType::ExplicitTag(_,_) => ASNTypeId::ExplicitTag
        }
    }
}

impl<'a> std::fmt::Display for ASNType<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            ASNType::Boolean(value) => {
                write!(f, "Boolean: {}", value)
            }
            ASNType::Sequence(_) => {
                write!(f, "Sequence")
            }
            ASNType::Set(_) => {
                write!(f, "Set")
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
            ASNType::Integer(cell) => write!(f, "Integer: {}", cell),
            ASNType::Null => {
                f.write_str("Null")
            },
            ASNType::ObjectIdentifier(id) => {
                write!(f, "ObjectIdentifier: {}", id)
            }
            ASNType::UTCTime(value) => {
                write!(f, "UTCTime: {}", value)
            }
            ASNType::BitString(_) => {
                f.write_str("BitString")
            }
            ASNType::OctetString(_) => {
                f.write_str("OctetString")
            }
            ASNType::ExplicitTag(u8, _) => {
                write!(f,"[{}]", u8)
            }
        }

    }
}

#[derive(Debug, PartialEq)]
pub enum ASNError {
    // these errors relate to core DER parsing
    BadBooleanLength(usize),
    BadBooleanValue(u8),
    EmptySequence,
    EmptySet,
    EndOfStream,
    ZeroLengthInteger,
    NullWithNonEmptyContents(usize),
    UnsupportedId(Identifier),
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
            ASNError::BadBooleanLength(len) => {
               write!(f, "Bad boolean length: {}", len)
            }
            ASNError::BadBooleanValue(value) => {
                write!(f, "Bad boolean value: {}", value)
            }
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
                write!(f, "NULL type w/ non-empty contents (length == {})", length)
            }
            ASNError::UnsupportedId(id) => {
                write!(f, "Unsupported id: {:?})", id)
            }
            ASNError::UnsupportedIndefiniteLength => {
                f.write_str("Encountered indefinite length encoding. Not allowed in DER.")
            }
            ASNError::ReservedLengthValue => {
                f.write_str("Length byte count of 127 is reserved")
            }
            ASNError::UnsupportedLengthByteCount(length) => {
                write!(f, "Length byte count of {} not supported", length)
            }
            ASNError::BadLengthEncoding(value) => {
                write!(f, "Length should be encoded as a single byte: {}", value)
            }
            ASNError::BadOidLength => {
                f.write_str("Bad OID length")
            }
            ASNError::BadUTF8(err) => {
                write!(f, "Bad UTF8 encoding: {}", err)
            }
            ASNError::BadUTCTime(err) => {
                write!(f, "Bad UTC time string: {}", err)
            }
            ASNError::BitStringUnusedBitsTooLarge(unused) => {
                write!(f, "Bit string w/ unused bits outside range [0..7]: {}", unused)
            }
            ASNError::EndOfStream => {
                f.write_str("Consumed all input before parsing required fields")
            }
            ASNError::UnexpectedType(expected, actual) => {
                write!(f, "Expected {:?}, but type is {:?}", expected, actual)
            }
            ASNError::ExpectedEnd(actual) => {
                write!(f, "Expected end of stream but type is {:?}", actual)
            }
        }
    }
}

