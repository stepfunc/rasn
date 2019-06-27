mod rasn {
    use std::str::Utf8Error;

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

    #[derive(Debug, PartialEq)]
    pub struct IntegerCell<'a> {
        bytes: &'a[u8]
    }

    impl<'a> IntegerCell<'a> {

        fn new(bytes: &'a[u8]) -> IntegerCell {
            IntegerCell{bytes}
        }

        fn as_i32(&self) -> Option<i32> {

            match self.bytes.len() {
                1 => Some(self.bytes[0] as i32),
                2 => Some(
                    ((self.bytes[0] as i32) << 8) | (self.bytes[1] as i32)
                ),
                3 => Some(
                    ((self.bytes[0] as i32) << 16) | ((self.bytes[1] as i32) << 8) | (self.bytes[2] as i32)
                ),
                4 => Some(
                    ((self.bytes[0] as i32) << 24) | ((self.bytes[1] as i32) << 16) | ((self.bytes[2] as i32) << 8) | (self.bytes[3] as i32)
                ),
                _ => None
            }
        }
    }

    #[derive(Debug, PartialEq)]
    enum ASNToken<'a> {
        BeginSequence(&'a[u8]),             // the interior data of the sequence
        EndSequence,
        BeginSet(&'a[u8]),                  // the interior data of the set
        EndSet,
        Integer(IntegerCell<'a>),
        PrintableString(&'a str),
        GenericTLV(&'static str, &'a[u8]),  // any TLV
    }

    #[derive(Debug, PartialEq)]
    enum ParseError<'a> {
        EmptySequence,
        EmptySet,
        ZeroLengthInteger,
        NonUniversalType(u8),
        UnsupportedUniversalType(u8),
        InsufficientBytes(usize, &'a[u8]), // the required length and the actual remaining bytes
        UnsupportedIndefiniteLength,
        ReservedLengthValue,
        UnsupportedLengthByteCount(u8),
        BadLengthEncoding(u8),
        BadUTF8(Utf8Error)
    }

    type ParseResult<'a, T> = Result<ParseToken<'a, T>, ParseError<'a>>;

    fn parse_ok<T>(value : T,  remainder: &[u8]) -> ParseResult<T> {
        Ok(ParseToken { value, remainder })
    }

    fn parse_one(input: &[u8]) -> ParseResult<ASNToken> {

        fn parse_seq(contents: &[u8]) -> Result<ASNToken, ParseError> {
            if contents.is_empty() {
                Err(ParseError::EmptySequence)
            } else {
                Ok(ASNToken::BeginSequence(contents))
            }
        }

        fn parse_set(contents: &[u8]) -> Result<ASNToken, ParseError> {
            if contents.is_empty() {
                Err(ParseError::EmptySequence)
            } else {
                Ok(ASNToken::BeginSet(contents))
            }
        }

        fn parse_integer(contents: &[u8]) -> Result<ASNToken, ParseError> {
            if contents.is_empty() {
                Err(ParseError::ZeroLengthInteger)
            }
            else {
                Ok(ASNToken::Integer(IntegerCell::new(contents)))
            }
        }

        fn parse_generic_tlv<'a>(name: &'static str, contents: &'a[u8]) -> Result<ASNToken<'a>, ParseError<'a>> {
           Ok(ASNToken::GenericTLV(name, contents))
        }

        if input.len() < 1 {
            return Err(ParseError::InsufficientBytes(2, input))
        }

        let typ : u8 = input[0];

        if typ & 0b11000000 != 0 {
            // non-universal type
            return Err(ParseError::NonUniversalType(typ))
        }

        let length = parse_length(&input[1..])?;

        if length.value > length.remainder.len() {
            return Err(ParseError::InsufficientBytes(length.value, length.remainder))
        }

        let content = &length.remainder[0..length.value];

        let result = match typ & 0b00111111 {

           // simple types
           0x02 => parse_integer(content),
           0x03 => parse_generic_tlv("BitString", content),
           0x04 => parse_generic_tlv("OctetString", content),
           0x05 => parse_generic_tlv("Null", content),
           0x06 => parse_generic_tlv("ObjectIdentifier", content),
           0x0C => parse_generic_tlv("UTF8String", content),
           0x13 => parse_generic_tlv("PrintableString", content),
           0x14 => parse_generic_tlv("T61String", content),
           0x16 => parse_generic_tlv("IA5String", content),
           0x17 => parse_generic_tlv("UTCTime", content),

           // structured types
           0x30 => parse_seq(content),
           0x31 => parse_set(content),

           x => Err(ParseError::UnsupportedUniversalType(x))
        };

        result.map(|value| ParseToken::new(value, &length.remainder[length.value..]))
    }

    fn parse_length(input: &[u8]) -> ParseResult<usize> {

        fn decode_one(input: &[u8]) -> ParseResult<usize> {
            let value = input[0];

            if value == 0 {
                return Err(ParseError::UnsupportedIndefiniteLength)
            }

            if value < 128 {
                return Err(ParseError::BadLengthEncoding(value)) // should have been encoded in single byte
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
            return Err(ParseError::InsufficientBytes(1, input))
        }

        let top_bit = input[0] & 0b10000000;
        let count_of_bytes = input[0] & 0b01111111;

        if top_bit == 0 {
            parse_ok(count_of_bytes as usize, &input[1..])
        }
        else {

            if count_of_bytes == 0 {
                return Err(ParseError::UnsupportedIndefiniteLength);
            }

            if count_of_bytes == 127 {
                return Err(ParseError::ReservedLengthValue)
            }

            let remainder = &input[1..];

            if remainder.len() < count_of_bytes as usize {
                return Err(ParseError::InsufficientBytes(count_of_bytes as usize, remainder))
            }

            match count_of_bytes {
                1 => decode_one(remainder),
                2 => decode_two(remainder),
                3 => decode_three(remainder),
                4 => decode_four(remainder),
                _ => Err(ParseError::UnsupportedLengthByteCount(count_of_bytes))
            }
        }
    }

    enum ParserState<'a> {
        Continue(&'a[u8]),
        EndSequence(&'a[u8]),
        EndSet(&'a[u8])
    }

    struct Parser<'a> {
        states: Vec<ParserState<'a>>
    }

    impl<'a> Parser<'a> {
        fn new(input: &'a[u8]) -> Parser {
            Parser { states: vec![ParserState::Continue(input)] }
        }
    }


    impl<'a> Iterator for Parser<'a> {

        type Item = ParseResult<'a, ASNToken<'a>>;


        fn next(&mut self) -> Option<Self::Item> {
            self.states.pop().map(
                |current| {
                    match current {
                        ParserState::Continue(pos) => {
                            match parse_one(pos) {
                                Err(e) => {
                                    self.states.clear();
                                    Err(e)
                                },
                                Ok(token) => match token.value {
                                    ASNToken::BeginSequence(contents) => {
                                        self.states.push(ParserState::EndSequence(token.remainder));
                                        if !contents.is_empty() {
                                            self.states.push(ParserState::Continue(contents));
                                        }
                                        Ok(token)
                                    },
                                    ASNToken::BeginSet(contents) => {
                                        self.states.push(ParserState::EndSet(token.remainder));
                                        if !contents.is_empty() {
                                            self.states.push(ParserState::Continue(contents));
                                        }
                                        Ok(token)
                                    }
                                    _ => {
                                        if token.remainder.len() > 0 {
                                            self.states.push(ParserState::Continue(token.remainder));
                                        }
                                        Ok(token)
                                    }
                                }
                            }
                        },
                        ParserState::EndSequence(remainder) => {
                            if !remainder.is_empty() {
                                self.states.push(ParserState::Continue(remainder));
                            }

                            parse_ok(ASNToken::EndSequence, remainder)
                        },
                        ParserState::EndSet(remainder) => {
                            if !remainder.is_empty() {
                                self.states.push(ParserState::Continue(remainder));
                            }

                            parse_ok(ASNToken::EndSet, remainder)
                        }
                    }
                }
            )
        }
    }


    #[cfg(test)]
    mod tests {
        use ::rasn::*;

        const TOP_BIT : u8 = 1 << 7;

        #[test]
        fn decode_length_on_empty_bytes_fails() {
            assert_eq!(parse_length(&[]), Err(ParseError::InsufficientBytes(1, &[])))
        }

        #[test]
        fn detects_indefinite_length() {
            assert_eq!(parse_length(&[0x80]), Err(ParseError::UnsupportedIndefiniteLength))
        }

        #[test]
        fn detects_reserved_length_of_127() {
            assert_eq!(parse_length(&[0xFF]), Err(ParseError::ReservedLengthValue))
        }

        #[test]
        fn decode_length_on_single_byte_returns_valid_result() {
            assert_eq!(parse_length(&[127, 0xDE, 0xAD]), parse_ok(127, &[0xDE, 0xAD]))
        }

        #[test]
        fn decode_length_on_count_of_one_returns_none_if_value_less_than_128() {
            assert_eq!(parse_length(&[TOP_BIT | 1, 127]), Err(ParseError::BadLengthEncoding(127)))
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
            assert_eq!(parse_length(&[TOP_BIT | 5, 0x01, 0x02, 0x03, 0x04, 0x05]), Err(ParseError::UnsupportedLengthByteCount(5)))
        }

        #[test]
        fn parse_one_fails_for_non_universal_type() {
            assert_eq!(parse_one(&[0xFF]), Err(ParseError::NonUniversalType(0xFF)))
        }

        #[test]
        fn parse_one_fails_for_unknown_universal_type() {
            assert_eq!(parse_one(&[0x3F, 0x00]), Err(ParseError::UnsupportedUniversalType(0x3F)))
        }

        #[test]
        fn parses_sequence_correctly() {
            assert_eq!(parse_one(&[0x30, 0x03, 0x02, 0x03, 0x04, 0x05, 0x06]), parse_ok(ASNToken::BeginSequence(&[0x02, 0x03, 0x04]), &[0x05, 0x06]))
        }

        #[test]
        fn parse_sequence_fails_if_insufficient_bytes() {
            assert_eq!(parse_one(&[0x30, 0x0F, 0xDE, 0xAD]), Err(ParseError::InsufficientBytes(0x0F, &[0xDE, 0xAD])))
        }

        const CERT_DATA : [u8; 534] = [
            0x30, 0x82, 0x02, 0x12, 0x30, 0x82, 0x01, 0x7b, 0x02, 0x02, 0x0d, 0xfa, 0x30, 0x0d, 0x06, 0x09,
            0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x05, 0x05, 0x00, 0x30, 0x81, 0x9b, 0x31, 0x0b,
            0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x4a, 0x50, 0x31, 0x0e, 0x30, 0x0c, 0x06,
            0x03, 0x55, 0x04, 0x08, 0x13, 0x05, 0x54, 0x6f, 0x6b, 0x79, 0x6f, 0x31, 0x10, 0x30, 0x0e, 0x06,
            0x03, 0x55, 0x04, 0x07, 0x13, 0x07, 0x43, 0x68, 0x75, 0x6f, 0x2d, 0x6b, 0x75, 0x31, 0x11, 0x30,
            0x0f, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x13, 0x08, 0x46, 0x72, 0x61, 0x6e, 0x6b, 0x34, 0x44, 0x44,
            0x31, 0x18, 0x30, 0x16, 0x06, 0x03, 0x55, 0x04, 0x0b, 0x13, 0x0f, 0x57, 0x65, 0x62, 0x43, 0x65,
            0x72, 0x74, 0x20, 0x53, 0x75, 0x70, 0x70, 0x6f, 0x72, 0x74, 0x31, 0x18, 0x30, 0x16, 0x06, 0x03,
            0x55, 0x04, 0x03, 0x13, 0x0f, 0x46, 0x72, 0x61, 0x6e, 0x6b, 0x34, 0x44, 0x44, 0x20, 0x57, 0x65,
            0x62, 0x20, 0x43, 0x41, 0x31, 0x23, 0x30, 0x21, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d,
            0x01, 0x09, 0x01, 0x16, 0x14, 0x73, 0x75, 0x70, 0x70, 0x6f, 0x72, 0x74, 0x40, 0x66, 0x72, 0x61,
            0x6e, 0x6b, 0x34, 0x64, 0x64, 0x2e, 0x63, 0x6f, 0x6d, 0x30, 0x1e, 0x17, 0x0d, 0x31, 0x32, 0x30,
            0x38, 0x32, 0x32, 0x30, 0x35, 0x32, 0x36, 0x35, 0x34, 0x5a, 0x17, 0x0d, 0x31, 0x37, 0x30, 0x38,
            0x32, 0x31, 0x30, 0x35, 0x32, 0x36, 0x35, 0x34, 0x5a, 0x30, 0x4a, 0x31, 0x0b, 0x30, 0x09, 0x06,
            0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x4a, 0x50, 0x31, 0x0e, 0x30, 0x0c, 0x06, 0x03, 0x55, 0x04,
            0x08, 0x0c, 0x05, 0x54, 0x6f, 0x6b, 0x79, 0x6f, 0x31, 0x11, 0x30, 0x0f, 0x06, 0x03, 0x55, 0x04,
            0x0a, 0x0c, 0x08, 0x46, 0x72, 0x61, 0x6e, 0x6b, 0x34, 0x44, 0x44, 0x31, 0x18, 0x30, 0x16, 0x06,
            0x03, 0x55, 0x04, 0x03, 0x0c, 0x0f, 0x77, 0x77, 0x77, 0x2e, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c,
            0x65, 0x2e, 0x63, 0x6f, 0x6d, 0x30, 0x5c, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7,
            0x0d, 0x01, 0x01, 0x01, 0x05, 0x00, 0x03, 0x4b, 0x00, 0x30, 0x48, 0x02, 0x41, 0x00, 0x9b, 0xfc,
            0x66, 0x90, 0x79, 0x84, 0x42, 0xbb, 0xab, 0x13, 0xfd, 0x2b, 0x7b, 0xf8, 0xde, 0x15, 0x12, 0xe5,
            0xf1, 0x93, 0xe3, 0x06, 0x8a, 0x7b, 0xb8, 0xb1, 0xe1, 0x9e, 0x26, 0xbb, 0x95, 0x01, 0xbf, 0xe7,
            0x30, 0xed, 0x64, 0x85, 0x02, 0xdd, 0x15, 0x69, 0xa8, 0x34, 0xb0, 0x06, 0xec, 0x3f, 0x35, 0x3c,
            0x1e, 0x1b, 0x2b, 0x8f, 0xfa, 0x8f, 0x00, 0x1b, 0xdf, 0x07, 0xc6, 0xac, 0x53, 0x07, 0x02, 0x03,
            0x01, 0x00, 0x01, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x05,
            0x05, 0x00, 0x03, 0x81, 0x81, 0x00, 0x14, 0xb6, 0x4c, 0xbb, 0x81, 0x79, 0x33, 0xe6, 0x71, 0xa4,
            0xda, 0x51, 0x6f, 0xcb, 0x08, 0x1d, 0x8d, 0x60, 0xec, 0xbc, 0x18, 0xc7, 0x73, 0x47, 0x59, 0xb1,
            0xf2, 0x20, 0x48, 0xbb, 0x61, 0xfa, 0xfc, 0x4d, 0xad, 0x89, 0x8d, 0xd1, 0x21, 0xeb, 0xd5, 0xd8,
            0xe5, 0xba, 0xd6, 0xa6, 0x36, 0xfd, 0x74, 0x50, 0x83, 0xb6, 0x0f, 0xc7, 0x1d, 0xdf, 0x7d, 0xe5,
            0x2e, 0x81, 0x7f, 0x45, 0xe0, 0x9f, 0xe2, 0x3e, 0x79, 0xee, 0xd7, 0x30, 0x31, 0xc7, 0x20, 0x72,
            0xd9, 0x58, 0x2e, 0x2a, 0xfe, 0x12, 0x5a, 0x34, 0x45, 0xa1, 0x19, 0x08, 0x7c, 0x89, 0x47, 0x5f,
            0x4a, 0x95, 0xbe, 0x23, 0x21, 0x4a, 0x53, 0x72, 0xda, 0x2a, 0x05, 0x2f, 0x2e, 0xc9, 0x70, 0xf6,
            0x5b, 0xfa, 0xfd, 0xdf, 0xb4, 0x31, 0xb2, 0xc1, 0x4a, 0x9c, 0x06, 0x25, 0x43, 0xa1, 0xe6, 0xb4,
            0x1e, 0x7f, 0x86, 0x9b, 0x16, 0x40
        ];


        #[test]
        fn iterates_over_x509() {

            let mut indent : usize = 0;

            let parser = Parser::new(&CERT_DATA);

            fn print_indent(indent: usize) {
                for _ in 0..indent {
                    print!("    ");
                }
            }

            for result in parser {
                match result {
                    Err(x) => println!("{:?}", x),
                    Ok(token) => match token.value {
                       ASNToken::BeginSequence(_) => {
                           print_indent(indent);
                           println!("BeginSequence");
                           indent += 1;
                       }
                       ASNToken::EndSequence =>  {
                           indent -= 1;
                           print_indent(indent);
                           println!("EndSequence");
                       }
                        ASNToken::BeginSet(_) => {
                            print_indent(indent);
                            println!("BeginSet");
                            indent += 1;
                        }
                        ASNToken::EndSet =>  {
                            indent -= 1;
                            print_indent(indent);
                            println!("EndSet");
                        }
                        ASNToken::Integer(cell) => {
                            print_indent(indent);
                            match cell.as_i32() {
                                Some(x) => println!("Integer: {}", x),
                                None => println!("Integer: {:?}", cell.bytes),
                            }

                        }
                        ASNToken::PrintableString(value) => {
                            print_indent(indent);
                            println!("PrintableString: {}", value);

                        }
                        ASNToken::GenericTLV(name, contents) => {
                           print_indent(indent);
                           println!("{} ({})", name, contents.len());
                        },
                    }
                }
            }

        }


    }
}




