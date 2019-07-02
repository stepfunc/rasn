
use chrono;
use std::str;

use types::{ASNError, ASNType, ASNInteger, ASNBitString, ASNObjectIdentifier};
use chrono::{DateTime, FixedOffset};

#[derive(Debug, PartialEq)]
struct ParseToken<'a, T> {
    value : T,
    remainder: &'a[u8]
}

impl<'a, T> ParseToken<'a, T> {
    fn new(value: T, remainder: &[u8]) -> ParseToken<T> {
        ParseToken {value, remainder}
    }
}

type ParseResult<'a, T> = Result<ParseToken<'a, T>, ASNError<'a>>;
type ASNResult<'a> = Result<ASNType<'a>, ASNError<'a>>;

fn parse_ok<T>(value : T,  remainder: &[u8]) -> ParseResult<T> {
    Ok(ParseToken { value, remainder })
}

fn parse_seq(contents: &[u8]) -> ASNResult {
    if contents.is_empty() {
        Err(ASNError::EmptySequence)
    } else {
        Ok(ASNType::Sequence(contents))
    }
}

fn parse_set(contents: &[u8]) -> ASNResult {
    if contents.is_empty() {
        Err(ASNError::EmptySet)
    } else {
        Ok(ASNType::Set(contents))
    }
}

fn parse_null(contents: &[u8]) -> ASNResult {
    if contents.is_empty() {
        Ok(ASNType::Null)
    }
    else {
        Err(ASNError::NullWithNonEmptyContents(contents))
    }
}

fn parse_integer(contents: &[u8]) -> ASNResult {
    if contents.is_empty() {
        Err(ASNError::ZeroLengthInteger)
    }
    else {
        Ok(ASNType::Integer(ASNInteger::new(contents)))
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

    match str::from_utf8(contents) {
        Ok(s) => match try_parse_all_variants(s){
            Ok(time) => Ok(ASNType::UTCTime(time)),
            Err(err) => Err(ASNError::BadUTCTime(err, s))
        }
        Err(x) => Err(ASNError::BadUTF8(x))
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
        return Err(ASNError::InsufficientBytes(0, contents))
    }

    let unused_bits = contents[0];
    if unused_bits > 7 {
        return Err(ASNError::BitStringUnusedBitsTooLarge(unused_bits));
    }

    Ok(ASNType::BitString(ASNBitString::new(unused_bits, &contents[1..])))
}

fn parse_object_identifier(contents: &[u8]) -> ASNResult {

    fn parse_remainder<'a>(contents: &'a[u8], items: &mut Vec<u32>) -> Result<(), ASNError<'a>> {

        fn parse_one(contents: &[u8]) -> ParseResult<u32> {
            let mut sum : u32 = 0;
            let mut count: u32 = 0;
            let mut cursor = contents;

            loop {

                // only allow 4*7 = 28 bits so that we don't overflow u32
                if count > 3 { return Err(ASNError::BadOidLength) };
                if cursor.is_empty() { return Err(ASNError::InsufficientBytes(1, cursor)) }

                let has_next : bool = (cursor[0] & 0b10000000) != 0;
                let value : u32 = (cursor[0] & 0b01111111) as u32;

                sum <<= 7;
                sum += value;

                count += 1;
                cursor = &cursor[1..];

                if !has_next {
                    return Ok(ParseToken::new(sum, &cursor))
                }
            }
        }

        let mut current = contents;

        while !current.is_empty() {
            match parse_one(current) {
                Ok(ParseToken { value, remainder }) => {
                    items.push(value);
                    current = remainder;
                },
                Err(err) => {
                    return Err(err)
                }
            }
        }

        Ok(())
    }

    if contents.is_empty() {
        return Err(ASNError::InsufficientBytes(1, contents))
    }

    let first = contents[0] / 40;
    let second = contents[0] % 40;

    let mut items : Vec<u32> = Vec::new();

    items.push(first as u32);
    items.push(second as u32);

    parse_remainder(&contents[1..], &mut items)?;

    Ok(ASNType::ObjectIdentifier(ASNObjectIdentifier::new(items)))
}

fn parse_length(input: &[u8]) -> ParseResult<usize> {

    fn decode_one(input: &[u8]) -> ParseResult<usize> {
        let value = input[0];

        if value == 0 {
            return Err(ASNError::UnsupportedIndefiniteLength)
        }

        if value < 128 {
            return Err(ASNError::BadLengthEncoding(value)) // should have been encoded in single byte
        }

        parse_ok(value as usize, &input[1..])
    }

    fn decode_two(input: &[u8]) -> ParseResult<usize> {
        let value = (input[0] as usize) << 8 | input[1] as usize;
        parse_ok(value, &input[2..])
    }

    fn decode_three(input: &[u8]) -> ParseResult<usize> {
        let value = ((input[0] as usize) << 16) | ((input[1] as usize) << 8) | (input[2] as usize);
        parse_ok(value, &input[3..])
    }

    fn decode_four(input: &[u8]) -> ParseResult<usize> {
        let value = ((input[0] as usize) << 24) | ((input[1] as usize) << 16) | ((input[2] as usize) << 8) | (input[3] as usize);
        parse_ok(value, &input[4..])
    }

    if input.len() < 1 {
        return Err(ASNError::InsufficientBytes(1, input))
    }

    let top_bit = input[0] & 0b10000000;
    let count_of_bytes = input[0] & 0b01111111;

    if top_bit == 0 {
        parse_ok(count_of_bytes as usize, &input[1..])
    }
    else {

        if count_of_bytes == 0 {
            return Err(ASNError::UnsupportedIndefiniteLength);
        }

        if count_of_bytes == 127 {
            return Err(ASNError::ReservedLengthValue)
        }

        let remainder = &input[1..];

        if remainder.len() < count_of_bytes as usize {
            return Err(ASNError::InsufficientBytes(count_of_bytes as usize, remainder))
        }

        match count_of_bytes {
            1 => decode_one(remainder),
            2 => decode_two(remainder),
            3 => decode_three(remainder),
            4 => decode_four(remainder),
            _ => Err(ASNError::UnsupportedLengthByteCount(count_of_bytes))
        }
    }
}

fn parse_one_type(input: &[u8]) -> ParseResult<ASNType> {

    if input.len() < 1 {
        return Err(ASNError::InsufficientBytes(2, input))
    }

    let typ : u8 = input[0];

    if typ & 0b11000000 != 0 {
        // non-universal type
        return Err(ASNError::NonUniversalType(typ))
    }

    let length = parse_length(&input[1..])?;

    if length.value > length.remainder.len() {
        return Err(ASNError::InsufficientBytes(length.value, length.remainder))
    }

    let contents = &length.remainder[0..length.value];

    let result = match typ & 0b00111111 {

        // simple types
        0x02 => parse_integer(contents),
        0x03 => parse_bit_string(contents),
        0x04 => Ok(ASNType::OctetString(contents)),
        0x05 => parse_null(contents),
        0x06 => parse_object_identifier(contents),
        0x0C => parse_string(contents, |s| ASNType::UTF8String(s)),
        0x13 => parse_string(contents, |s| ASNType::PrintableString(s)),
        0x16 => parse_string(contents, |s| ASNType::IA5String(s)),
        0x17 => parse_utc_time(contents),

        // structured types
        0x30 => parse_seq(contents),
        0x31 => parse_set(contents),

        x => Err(ASNError::UnsupportedUniversalType(x))
    };

    result.map(|value| ParseToken::new(value, &length.remainder[length.value..]))
}

pub struct Parser<'a> {
    cursor: &'a[u8]
}

impl<'a> Parser<'a> {
    pub fn new(input: &'a[u8]) -> Parser {
        Parser { cursor: input }
    }

    pub fn expect_sequence(&mut self) -> Result<&'a[u8], ASNError<'a>> {
        match self.next() {
            Some(Ok(ASNType::Sequence(contents))) => Ok(contents),
            Some(Ok(_)) => Err(ASNError::UnexpectedType),
            Some(Err(err)) => Err(err),
            None => Err(ASNError::EndOfStream)
        }
    }

    pub fn expect_object_identifier(&mut self) -> Result<ASNObjectIdentifier, ASNError<'a>> {
        match self.next() {
            Some(Ok(ASNType::ObjectIdentifier(id))) => Ok(id),
            Some(Ok(_)) => Err(ASNError::UnexpectedType),
            Some(Err(err)) => Err(err),
            None => Err(ASNError::EndOfStream)
        }
    }

    pub fn expect_integer(&mut self) -> Result<ASNInteger<'a>, ASNError<'a>> {
        match self.next() {
            Some(Ok(ASNType::Integer(x))) => Ok(x),
            Some(Ok(_)) => Err(ASNError::UnexpectedType),
            Some(Err(err)) => Err(err),
            None => Err(ASNError::EndOfStream)
        }
    }

    pub fn expect_bit_string(&mut self) -> Result<ASNBitString<'a>, ASNError<'a>> {
        match self.next() {
            Some(Ok(ASNType::BitString(bs))) => Ok(bs),
            Some(Ok(_)) => Err(ASNError::UnexpectedType),
            Some(Err(err)) => Err(err),
            None => Err(ASNError::EndOfStream)
        }
    }

    pub fn expect_utc_time(&mut self) -> Result<DateTime<FixedOffset>, ASNError<'a>> {
        match self.next() {
            Some(Ok(ASNType::UTCTime(time))) => Ok(time),
            Some(Ok(_)) => Err(ASNError::UnexpectedType),
            Some(Err(err)) => Err(err),
            None => Err(ASNError::EndOfStream)
        }
    }

    pub fn expect_end(&mut self) -> Result<(), ASNError<'a>> {
        match self.next() {
            None => Ok(()),
            Some(Err(err)) => Err(err),
            Some(Ok(_)) => Err(ASNError::UnexpectedType),
        }
    }
}


impl<'a> Iterator for Parser<'a> {

    type Item = Result<ASNType<'a>, ASNError<'a>>;


    fn next(&mut self) -> Option<Self::Item> {

        if self.cursor.is_empty() {
            return None
        }

        match parse_one_type(self.cursor) {
            Err(e) => {
                self.cursor = &[];
                Some(Err(e))
            },
            Ok(token) => {
                self.cursor = token.remainder;
                Some(Ok(token.value))
            }
        }
    }
}




#[cfg(test)]
mod tests {

    use parser::*;
    use types::*;

    const TOP_BIT: u8 = 1 << 7;

    #[test]
    fn decode_length_on_empty_bytes_fails() {
        assert_eq!(parse_length(&[]), Err(ASNError::InsufficientBytes(1, &[])))
    }

    #[test]
    fn detects_indefinite_length() {
        assert_eq!(parse_length(&[0x80]), Err(ASNError::UnsupportedIndefiniteLength))
    }

    #[test]
    fn detects_reserved_length_of_127() {
        assert_eq!(parse_length(&[0xFF]), Err(ASNError::ReservedLengthValue))
    }

    #[test]
    fn decode_length_on_single_byte_returns_valid_result() {
        assert_eq!(parse_length(&[127, 0xDE, 0xAD]), parse_ok(127, &[0xDE, 0xAD]))
    }

    #[test]
    fn decode_length_on_count_of_one_returns_none_if_value_less_than_128() {
        assert_eq!(parse_length(&[TOP_BIT | 1, 127]), Err(ASNError::BadLengthEncoding(127)))
    }

    #[test]
    fn decode_length_on_count_of_one_succeeds_if_value_greater_than_127() {
        assert_eq!(parse_length(&[TOP_BIT | 1, 128]), parse_ok(128, &[]))
    }

    #[test]
    fn decode_length_on_count_of_two_succeeds() {
        assert_eq!(parse_length(&[TOP_BIT | 2, 0x01, 0x02, 0x03]), parse_ok(0x0102, &[0x03]))
    }

    #[test]
    fn decode_length_on_count_of_three_succeeds() {
        assert_eq!(parse_length(&[TOP_BIT | 3, 0x01, 0x02, 0x03, 0x04]), parse_ok(0x010203, &[0x04]))
    }

    #[test]
    fn decode_length_on_count_of_four_succeeds() {
        assert_eq!(parse_length(&[TOP_BIT | 4, 0x01, 0x02, 0x03, 0x04, 0x05]), parse_ok(0x01020304, &[0x05]))
    }

    #[test]
    fn decode_length_on_count_of_five_fails() {
        assert_eq!(parse_length(&[TOP_BIT | 5, 0x01, 0x02, 0x03, 0x04, 0x05]), Err(ASNError::UnsupportedLengthByteCount(5)))
    }

    #[test]
    fn parse_one_fails_for_non_universal_type() {
        assert_eq!(parse_one_type(&[0xFF]), Err(ASNError::NonUniversalType(0xFF)))
    }

    #[test]
    fn parse_one_fails_for_unknown_universal_type() {
        assert_eq!(parse_one_type(&[0x3F, 0x00]), Err(ASNError::UnsupportedUniversalType(0x3F)))
    }

    #[test]
    fn parses_sequence_correctly() {
        assert_eq!(parse_one_type(&[0x30, 0x03, 0x02, 0x03, 0x04, 0x05, 0x06]), parse_ok(ASNType::Sequence(&[0x02, 0x03, 0x04]), &[0x05, 0x06]))
    }

    #[test]
    fn parse_sequence_fails_if_insufficient_bytes() {
        assert_eq!(parse_one_type(&[0x30, 0x0F, 0xDE, 0xAD]), Err(ASNError::InsufficientBytes(0x0F, &[0xDE, 0xAD])));
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
                Ok(ASNType::UTCTime(
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
            Ok(ASNType::ObjectIdentifier(ASNObjectIdentifier::new([1, 3, 6, 1, 4, 1, 311, 21, 20].to_vec())))
        );

        // sha1WithRSAEncryption
        assert_eq!(
            parse_object_identifier(&[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x05]),
            Ok(ASNType::ObjectIdentifier(ASNObjectIdentifier::new([1, 2, 840, 113549, 1, 1, 5].to_vec())))
        );
    }
}
