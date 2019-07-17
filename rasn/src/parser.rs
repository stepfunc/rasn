
use chrono;
use std::str;

use reader::Reader;
use types::*;
use types::ASNError::UnsupportedId;

type ASNResult<'a> = Result<ASNType<'a>, ASNError>;

fn parse_seq(contents: &[u8]) -> ASNResult {
    if contents.is_empty() {
        Err(ASNError::EmptySequence)
    } else {
        Ok(Sequence::new(contents))
    }
}

fn parse_set(contents: &[u8]) -> ASNResult {
    if contents.is_empty() {
        Err(ASNError::EmptySet)
    } else {
        Ok(Set::new(contents))
    }
}

fn parse_null(contents: &[u8]) -> ASNResult {
    if contents.is_empty() {
        Ok(ASNType::Null)
    }
    else {
        Err(ASNError::NullWithNonEmptyContents(contents.len()))
    }
}

fn parse_boolean(contents: &[u8]) -> ASNResult {
    match contents {
        [0xFF] => Ok(Boolean::new(true)),
        [0x00] => Ok(Boolean::new(false)),
        [x] => Err(ASNError::BadBooleanValue(*x)),
        _ => Err(ASNError::BadBooleanLength(contents.len()))
    }
}

fn parse_integer(contents: &[u8]) -> ASNResult {
    if contents.is_empty() {
        Err(ASNError::ZeroLengthInteger)
    }
    else {
        Ok(Integer::new(ASNInteger::new(contents)))
    }
}

const UTC_WITH_SECONDS : &str = "%y%m%d%H%M%SZ";
const UTC_WITHOUT_SECONDS : &str = "%y%m%d%H%MZ";
const TZ_WITH_SECONDS: &str = "%y%m%d%H%M%S%z";
const TZ_WITHOUT_SECONDS: &str = "%y%m%d%H%M%z";

fn parse_utc_time(contents: &[u8]) -> ASNResult {

    fn try_parse_all_variants(s: &str) -> Result<chrono::DateTime<chrono::FixedOffset>, chrono::ParseError> {
        // try the explicitly UTC variant
        chrono::NaiveDateTime::parse_from_str(s,UTC_WITH_SECONDS)
            .or_else(|_|  chrono::NaiveDateTime::parse_from_str(s, UTC_WITHOUT_SECONDS))
            .map(|t| chrono::DateTime::from_utc(t, chrono::FixedOffset::east(0)))
            .or_else(|_| chrono::DateTime::parse_from_str(s,TZ_WITH_SECONDS))
            .or_else(|_| chrono::DateTime::parse_from_str(s, TZ_WITHOUT_SECONDS))
    }

    match try_parse_all_variants(str::from_utf8(contents)?) {
        Ok(time) => Ok(UtcTime::new(time)),
        Err(err) => Err(ASNError::BadUTCTime(err))
    }
}

fn parse_string<T : Fn(&str) -> ASNType>(contents: &[u8], create: T) -> ASNResult {
    match str::from_utf8(contents) {
        Ok(x) => Ok(create(x)),
        Err(x) => Err(ASNError::BadUTF8(x))
    }
}

fn parse_bit_string(contents: &[u8]) -> ASNResult {
    if contents.is_empty() {
        return Err(ASNError::EndOfStream)
    }

    let unused_bits = contents[0];
    if unused_bits > 7 {
        return Err(ASNError::BitStringUnusedBitsTooLarge(unused_bits));
    }

    Ok(BitString::new(ASNBitString::new(unused_bits, &contents[1..])))
}

fn parse_object_identifier(contents: &[u8]) -> ASNResult {

    fn parse_one<'a>(reader: &mut Reader) -> Result<u32, ASNError> {
        let mut sum : u32 = 0;
        let mut count: u32 = 0;
        loop {

            // only allow 4*7 = 28 bits so that we don't overflow u32
            if count > 3 { return Err(ASNError::BadOidLength) };

            let next_byte = reader.read_byte()?;
            let has_next : bool = (next_byte & 0b10000000) != 0;
            let value : u32 = (next_byte & 0b01111111) as u32;

            sum <<= 7;
            sum += value;

            count += 1;

            if !has_next {
                return Ok(sum)
            }
        }
    }

    let mut reader = Reader::new(contents);

    let mut items : Vec<u32> = Vec::new();

    let first_byte = reader.read_byte()?;

    items.push((first_byte / 40) as u32);
    items.push((first_byte % 40) as u32);

    while !reader.is_empty() {
        items.push(parse_one(&mut reader)?);
    }

    Ok(ObjectIdentifier::new(ASNObjectIdentifier::new(items)))
}

fn parse_length(reader: &mut Reader) -> Result<usize, ASNError> {

    let first_byte = reader.read_byte()?;

    let top_bit = first_byte & 0b10000000;
    let count_of_bytes = (first_byte & 0b01111111) as usize;

    if top_bit == 0 {
        Ok(count_of_bytes)
    }
    else {

        if count_of_bytes == 0 {
            return Err(ASNError::UnsupportedIndefiniteLength);
        }

        if count_of_bytes == 127 {
            return Err(ASNError::ReservedLengthValue)
        }

        if count_of_bytes < 1 || count_of_bytes > 4 {
            return Err(ASNError::UnsupportedLengthByteCount(count_of_bytes))
        }

        let mut value : usize = 0;

        for _ in 0 .. count_of_bytes {
            value <<= 8;
            value |= reader.read_byte()? as usize;
        }

        if value == 0 {
            return Err(ASNError::UnsupportedIndefiniteLength)
        }

        if value < 128 {
            return Err(ASNError::BadLengthEncoding(value)) // should have been encoded in single byte
        }

        Ok(value)
    }
}

fn parse_one_type<'a>(reader: &mut Reader<'a>) -> ASNResult<'a> {

    fn get_contents<'a>(reader: &mut Reader<'a>) -> Result<&'a[u8], ASNError> {
        let length = parse_length(reader)?;
        Ok(reader.take(length)?)
    }

    let id = Identifier::from(reader.read_byte()?);

    match read_type(&id) {
        Some(asn_type) => {
            let contents = get_contents(reader)?;

            match asn_type {
                ASNTypeId::Boolean => parse_boolean(contents),
                ASNTypeId::Integer => parse_integer(contents),
                ASNTypeId::BitString => parse_bit_string(contents),
                ASNTypeId::OctetString => Ok(OctetString::new(contents)),
                ASNTypeId::Null => parse_null(contents),
                ASNTypeId::ObjectIdentifier => parse_object_identifier(contents),
                ASNTypeId::UTF8String => parse_string(contents, |s| ASNType::UTF8String(s)),
                ASNTypeId::PrintableString => parse_string(contents, |s| ASNType::PrintableString(s)),
                ASNTypeId::IA5String => parse_string(contents, |s| ASNType::IA5String(s)),
                ASNTypeId::UTCTime => parse_utc_time(contents),

                ASNTypeId::Sequence => parse_seq(contents),
                ASNTypeId::Set => parse_set(contents),

                ASNTypeId::ExplicitTag => Ok(ExplicitTag::new(ASNExplicitTag::new(id.tag, contents)))
            }
        },
        None => Err(ASNError::UnsupportedId(id))
    }
}

fn read_type(id: &Identifier) -> Option<ASNTypeId> {
    match id {
        Identifier{ class: TagClass::Universal, pc: PC::Primitive, tag} => {
            match tag {
                0x01 => Some(ASNTypeId::Boolean),
                0x02 => Some(ASNTypeId::Integer),
                0x03 => Some(ASNTypeId::BitString),
                0x04 => Some(ASNTypeId::OctetString),
                0x05 => Some(ASNTypeId::Null),
                0x06 => Some(ASNTypeId::ObjectIdentifier),
                0x0C => Some(ASNTypeId::UTF8String),
                0x13 => Some(ASNTypeId::PrintableString),
                0x16 => Some(ASNTypeId::IA5String),
                0x17 => Some(ASNTypeId::UTCTime),

                _ => None
            }
        },
        Identifier{ class: TagClass::Universal, pc: PC::Constructed, tag} => {
            match tag {

                0x10 => Some(ASNTypeId::Sequence),
                0x11 => Some(ASNTypeId::Set),

                _ => None
            }
        },

        Identifier{ class: TagClass::ContextSpecific, pc: PC::Constructed, tag: _} => {
            Some(ASNTypeId::ExplicitTag)
        },

        _ => None
    }
}

pub struct Parser<'a> {
    reader: Reader<'a>
}

pub fn parse_all<'a, T>(input: &'a[u8], parse: fn(&mut Parser)-> Result<T, ASNError>) -> Result<T,ASNError> {
    let mut parser = Parser::new(input);
    let value = parse(&mut parser)?;
    parser.expect_end()?;
    Ok(value)
}

impl<'a> Parser<'a> {

    pub fn new(input: &'a[u8]) -> Parser {
        Parser { reader: Reader::new(input) }
    }

    pub fn unwrap_outer_sequence(input: &'a[u8]) -> Result<Parser, ASNError> {
        let mut parser = Parser::new(input);
        let bytes = parser.expect::<Sequence>()?;
        parser.expect_end()?;
        Ok(Parser::new(bytes))
    }

    pub fn unwrap_outer_set(input: &'a[u8]) -> Result<Parser, ASNError> {
        let mut parser = Parser::new(input);
        let bytes = parser.expect::<Set>()?;
        parser.expect_end()?;
        Ok(Parser::new(bytes))
    }

    pub fn get_explicitly_tagged_integer_or_default(&mut self, tag: u8, default: i32) -> Result<i32, ASNError> {
        match self.get_optional_explicit_tag(tag)? {
            Some(tag) => {
                let mut parser = Parser::new(tag.contents);
                let value = parser.expect::<Integer>()?;
                match value.as_i32() {
                    Some(x) => Ok(x),
                    None => Err(ASNError::IntegerTooLarge(value.bytes.len()))
                }
            },
            None => Ok(default)
        }
    }

    pub fn get_optional_explicit_tag(&mut self, tag: u8) -> Result<Option<ASNExplicitTag<'a>>, ASNError> {
        if self.reader.is_empty() {
            return Ok(None);
        }

        let id = Identifier::from(self.reader.peek_or_fail()?);

        match read_type(&id) {
            Some(ASNTypeId::ExplicitTag) if id.tag == tag => Ok(Some(self.expect::<ExplicitTag>()?)),
            Some(_) => Ok(None),
            None => Err(UnsupportedId(id)),
        }
    }

    pub fn get_optional_or_default<T : ASNNewType<'a>>(&mut self, default: T::Item) -> Result<T::Item, ASNError> {
        match self.get_optional::<T>()? {
            Some(value) => Ok(value),
            None => Ok(default),
        }
    }

    pub fn get_optional<T : ASNNewType<'a>>(&mut self) -> Result<Option<T::Item>, ASNError> {
        if self.reader.is_empty() {
            return Ok(None);
        }

        let id = Identifier::from(self.reader.peek_or_fail()?);

        match read_type(&id) {
            Some(ref id) if *id == T::get_id() => Ok(Some(self.expect::<T>()?)),
            Some(_) => Ok(None),
            None => Err(UnsupportedId(id)),
        }
    }

    pub fn expect<T : ASNNewType<'a>>(&mut self) -> Result<T::Item, ASNError> {
        match self.expect_any() {
            Ok(asn_type) => {
                let id = asn_type.get_id();
                match T::get_value(asn_type) {
                    Some(value) => Ok(value),
                    None => Err(ASNError::UnexpectedType(T::get_id(), id)),
                }
            }
            Err(err) => Err(err),
        }
    }

    pub fn expect_or_end<T : ASNNewType<'a>>(&mut self) -> Result<Option<T::Item>, ASNError> {
        match self.expect::<T>() {
            Ok(value) => Ok(Some(value)),
            Err(ASNError::EndOfStream) => Ok(None),
            Err(err) => Err(err),
        }
    }

    pub fn expect_any(&mut self) -> Result<ASNType<'a>, ASNError> {
        match self.next() {
            Some(Ok(asn)) => Ok(asn),
            Some(Err(err)) => Err(err),
            None => Err(ASNError::EndOfStream)
        }
    }

    pub fn expect_any_or_end(&mut self) -> Result<Option<ASNType<'a>>, ASNError> {
        match self.next() {
            Some(Ok(asn)) => Ok(Some(asn)),
            Some(Err(err)) => Err(err),
            None => Ok(None)
        }
    }

    pub fn expect_end(&mut self) -> Result<(), ASNError> {
        match self.next() {
            None => Ok(()),
            Some(Err(err)) => Err(err),
            Some(Ok(asn)) => Err(ASNError::ExpectedEnd(asn.get_id())),
        }
    }
}

impl<'a> Iterator for Parser<'a> {
    type Item = Result<ASNType<'a>, ASNError>;

    fn next(&mut self) -> Option<Self::Item> {

        if self.reader.is_empty() {
            return None
        }

        match parse_one_type(&mut self.reader) {
            Err(e) => {
                self.reader.clear();
                Some(Err(e))
            },
            Ok(token) => Some(Ok(token))
        }
    }
}

#[cfg(test)]
mod tests {

    use reader::Reader;
    use parser::*;
    use types::{ASNError, Identifier, TagClass, PC, ASNExplicitTag, Sequence, ExplicitTag, UtcTime, ObjectIdentifier, ASNObjectIdentifier};

    const TOP_BIT: u8 = 1 << 7;

    #[test]
    fn decode_length_on_empty_bytes_fails() {
        let mut reader = Reader::new(&[]);
        assert_eq!(parse_length(&mut reader), Err(ASNError::EndOfStream));
    }

    #[test]
    fn detects_indefinite_length() {
        let mut reader = Reader::new(&[0x80]);
        assert_eq!(parse_length(&mut reader), Err(ASNError::UnsupportedIndefiniteLength))
    }

    #[test]
    fn detects_reserved_length_of_127() {
        let mut reader = Reader::new(&[0xFF]);
        assert_eq!(parse_length(&mut reader), Err(ASNError::ReservedLengthValue))
    }

    #[test]
    fn decode_length_on_single_byte_returns_valid_result() {
        let mut reader = Reader::new(&[127, 0xDE, 0xAD]);
        assert_eq!(parse_length(&mut reader), Ok(127));
        assert_eq!(reader.remainder(), &[0xDE, 0xAD]);
    }

    #[test]
    fn decode_length_on_count_of_one_returns_none_if_value_less_than_128() {
        let mut reader = Reader::new(&[TOP_BIT | 1, 127]);
        assert_eq!(parse_length(&mut reader), Err(ASNError::BadLengthEncoding(127)))
    }

    #[test]
    fn decode_length_on_count_of_one_succeeds_if_value_greater_than_127() {
        let mut reader = Reader::new(&[TOP_BIT | 1, 128]);
        assert_eq!(parse_length(&mut reader), Ok(128));
        assert!(reader.is_empty());
    }

    #[test]
    fn decode_length_on_count_of_two_succeeds() {
        let mut reader = Reader::new(&[TOP_BIT | 2, 0x01, 0x02, 0x03]);
        assert_eq!(parse_length(&mut reader), Ok(0x0102));
        assert_eq!(reader.remainder(), &[0x03]);
    }

    #[test]
    fn decode_length_on_count_of_three_succeeds() {
        let mut reader = Reader::new(&[TOP_BIT | 3, 0x01, 0x02, 0x03, 0x04]);
        assert_eq!(parse_length(&mut reader), Ok(0x010203));
        assert_eq!(reader.remainder(), &[0x04]);
    }

    #[test]
    fn decode_length_on_count_of_four_succeeds() {
        let mut reader = Reader::new(&[TOP_BIT | 4, 0x01, 0x02, 0x03, 0x04, 0x05]);
        assert_eq!(parse_length(&mut reader), Ok(0x01020304));
        assert_eq!(reader.remainder(), &[0x05]);
    }

    #[test]
    fn decode_length_on_count_of_five_fails() {
        let mut reader = Reader::new(&[TOP_BIT | 5, 0x01, 0x02, 0x03, 0x04, 0x05]);
        assert_eq!(parse_length(&mut reader), Err(ASNError::UnsupportedLengthByteCount(5)))
    }

    #[test]
    fn parse_one_fails_for_non_universal_type() {
        let mut reader = Reader::new(&[0xFF]);
        assert_eq!(parse_one_type(&mut reader), Err(ASNError::UnsupportedId(Identifier::new(TagClass::Private, PC::Constructed, 0x1F))))
    }

    #[test]
    fn parse_one_fails_for_unknown_universal_type() {
        let mut reader = Reader::new(&[0x1F, 0x00]);
        assert_eq!(parse_one_type(&mut reader), Err(ASNError::UnsupportedId(Identifier::new(TagClass::Universal, PC::Primitive, 0x1F))))
    }

    #[test]
    fn parses_sequence_correctly() {
        let mut reader = Reader::new(&[0x30, 0x03, 0x02, 0x03, 0x04, 0x05, 0x06]);
        assert_eq!(parse_one_type(&mut reader), Ok(Sequence::new(&[0x02, 0x03, 0x04])));
        assert_eq!(reader.remainder(), &[0x05, 0x06]);
    }

    #[test]
    fn parse_sequence_fails_if_insufficient_bytes() {
        let mut reader = Reader::new(&[0x30, 0x0F, 0xDE, 0xAD]);
        assert_eq!(parse_one_type(&mut reader), Err(ASNError::EndOfStream));
    }

    #[test]
    fn parses_explicit_tag() {
        let mut reader = Reader::new(&[0xA1, 0x02, 0xCA, 0xFE]);
        assert_eq!(parse_one_type(&mut reader), Ok(ExplicitTag::new(ASNExplicitTag::new(1, &[0xCA, 0xFE]))));
    }

    #[test]
    fn parses_utc_time() {
        let utc_with_seconds = "990102052345Z";
        let utc_without_seconds = "9901020523Z";
        let tz_positive_with_seconds = "990102052345+0000";
        let tz_positive_without_seconds = "9901020523+0000";
        let tz_negative_with_seconds = "990102052345-0000";
        let tz_negative_without_seconds = "9901020523-0000";

        fn test_variant(value: &str, seconds: u32) {
            assert_eq!(
                parse_utc_time(value.as_bytes()),
                Ok(UtcTime::new(
                    chrono::DateTime::from_utc(
                        chrono::NaiveDate::from_ymd(1999, 01, 02).and_hms(5, 23, seconds),
                        chrono::FixedOffset::east(0)
                    )
                ))
            );
        }

        // parses the explicit timezone version
        test_variant(utc_with_seconds, 45);
        test_variant(utc_without_seconds, 00);

        test_variant(tz_positive_with_seconds, 45);
        test_variant(tz_positive_without_seconds, 00);

        test_variant(tz_negative_with_seconds, 45);
        test_variant(tz_negative_without_seconds, 00);
    }

    #[test]
    fn parses_known_object_identifiers() {
        // Microsoft: szOID_REQUEST_CLIENT_INFO
        assert_eq!(
            parse_object_identifier(&[0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x15, 0x14]),
            Ok(ObjectIdentifier::new(ASNObjectIdentifier::new([1, 3, 6, 1, 4, 1, 311, 21, 20].to_vec())))
        );

        // sha1WithRSAEncryption
        assert_eq!(
            parse_object_identifier(&[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x05]),
            Ok(ObjectIdentifier::new(ASNObjectIdentifier::new([1, 2, 840, 113549, 1, 1, 5].to_vec())))
        );
    }
}
