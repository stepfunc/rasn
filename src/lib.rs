mod rasn {
    use std::io::Read;

    #[derive(Debug, PartialEq)]
    enum IdentifierType {
        Universal,
        Application,
        ContextSpecific,
        Private
    }

    #[derive(Debug, PartialEq)]
    enum SimpleType {
        Integer,
        BitString,
        OctetString,
        Null,
        ObjectIdentifier,
        Sequence,
        Set,
        PrintableString,
        T61String,
        IA5String,
        UTCTime,
        Unknown(u8)
    }

    fn get_identifier_type(value: u8) -> IdentifierType {
        match value & 0b11000000 {
            0b01000000 => IdentifierType::Application,
            0b10000000 => IdentifierType::ContextSpecific,
            0b11000000 => IdentifierType::Private,
            _ => IdentifierType::Universal
        }
    }

    fn get_simple_type(value: u8) -> SimpleType {
        let masked: u8 = value & 0b00111111;

        match masked {
           0x02 => SimpleType::Integer,
           0x03 => SimpleType::BitString,
           0x04 => SimpleType::OctetString,
           0x05 => SimpleType::Null,
           0x06 => SimpleType::ObjectIdentifier,
           0x10 => SimpleType::Sequence,
           0x11 => SimpleType::Set,
           0x13 => SimpleType::PrintableString,
           0x14 => SimpleType::T61String,
           0x16 => SimpleType::IA5String,
           0x17 => SimpleType::UTCTime,
           _ => SimpleType::Unknown(masked)
        }
    }

    #[derive(Debug, PartialEq)]
    struct ParseResult<'a, T> {
        value : T,
        remainder: &'a[u8]
    }


    fn decode_length(input: &[u8]) -> Option<ParseResult<u32>> {

        fn decode_one(input: &[u8]) -> Option<ParseResult<u32>> {
            let value = input[0] as u32;
            if value <= 127 {
                None // should have been encoded in single byte
            } else {
                Some(ParseResult{value, remainder: &input[1..]})
            }
        }

        fn decode_two(input: &[u8]) -> Option<ParseResult<u32>> {
            let value = (input[0] as u32) << 8 | input[1] as u32;

            Some(ParseResult{value, remainder: &input[2..]})
        }

        fn decode_three(input: &[u8]) -> Option<ParseResult<u32>> {
            let value = ((input[0] as u32) << 16) | ((input[1] as u32) << 8) | (input[2] as u32);
            Some(ParseResult{value, remainder: &input[3..]})
        }

        fn decode_four(input: &[u8]) -> Option<ParseResult<u32>> {
            let value = ((input[0] as u32) << 24) | ((input[1] as u32) << 16) | ((input[2] as u32) << 8) | (input[3] as u32);
            Some(ParseResult{value, remainder: &input[4..]})
        }

        if input.len() < 1 {
            return None
        }

        let top = input[0] & 0b10000000;
        let count = input[0] & 0b01111111;

        if top == 0 {
            Some(ParseResult{value: count as u32, remainder: &input[1..]})
        }
        else {

            let remainder = &input[1..];

            if remainder.len() < count as usize {
                return None
            }

            match count {
                1 => decode_one(remainder),
                2 => decode_two(remainder),
                3 => decode_three(remainder),
                4 => decode_four(remainder),
                _ => None
            }
        }
    }


    #[cfg(test)]
    mod tests {
        use ::rasn::*;

        const TOP_BIT : u8 = 1 << 7;

        #[test]
        fn get_identifier_type_decodes_correctly() {
            assert_eq!(get_identifier_type(1 << 6), IdentifierType::Application);
            assert_eq!(get_identifier_type(1 << 7), IdentifierType::ContextSpecific);
            assert_eq!(get_identifier_type(0xFF), IdentifierType::Private);
            assert_eq!(get_identifier_type(3), IdentifierType::Universal);
        }

        #[test]
        fn get_simple_type_decodes_correctly() {
            assert_eq!(get_simple_type(0x02), SimpleType::Integer);
            assert_eq!(get_simple_type(0x03), SimpleType::BitString);
            assert_eq!(get_simple_type(0xFF), SimpleType::Unknown(0x3F));
        }

        #[test]
        fn decode_length_on_empty_bytes_returns_none() {
            assert_eq!(decode_length(&[]), None)
        }

        #[test]
        fn decode_length_on_single_byte_returns_valid_result() {
            assert_eq!(decode_length(&[127, 0xDE, 0xAD]), Some(ParseResult {value: 127, remainder: &[0xDE, 0xAD]}))
        }

        #[test]
        fn decode_length_on_count_of_one_returns_none_if_value_less_than_128() {
            assert_eq!(decode_length(&[TOP_BIT | 1, 127]), None)
        }

        #[test]
        fn decode_length_on_count_of_one_succeeds_if_value_greater_than_127() {
            assert_eq!(decode_length(&[TOP_BIT | 1, 128]), Some(ParseResult {value: 128, remainder: &[]}))
        }

        #[test]
        fn decode_length_on_count_of_two_succeeds() {
            assert_eq!(decode_length(&[TOP_BIT | 2, 0x01, 0x02, 0x03]), Some(ParseResult {value: 0x0102, remainder: &[0x03]}))
        }

        #[test]
        fn decode_length_on_count_of_three_succeeds() {
            assert_eq!(decode_length(&[TOP_BIT | 3, 0x01, 0x02, 0x03, 0x04]), Some(ParseResult {value: 0x010203, remainder: &[0x04]}))
        }

        #[test]
        fn decode_length_on_count_of_four_succeeds() {
            assert_eq!(decode_length(&[TOP_BIT | 4, 0x01, 0x02, 0x03, 0x04, 0x05]), Some(ParseResult {value: 0x01020304, remainder: &[0x05]}))
        }

        #[test]
        fn decode_length_on_count_of_five_fails() {
            assert_eq!(decode_length(&[TOP_BIT | 5, 0x01, 0x02, 0x03, 0x04, 0x05]), None)
        }
    }
}




