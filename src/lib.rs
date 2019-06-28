mod rasn {

    use std::str;
    use rasn::ParseError::InsufficientBytes;

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
    enum ASNType<'a> {
        Sequence(&'a[u8]),             // the interior data of the sequence
        Set(&'a[u8]),                  // the interior data of the set
        Integer(IntegerCell<'a>),
        PrintableString(&'a str),
        IA5String(&'a str),
        UTF8String(&'a str),
        Null,
        GenericTLV(&'static str, &'a[u8]),  // any TLV
        ObjectIdentifier(Vec<u32>)
    }

    #[derive(Debug, PartialEq)]
    enum ParseError<'a> {
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
        BadUTF8(str::Utf8Error)
    }

    type ParseResult<'a, T> = Result<ParseToken<'a, T>, ParseError<'a>>;

    fn parse_ok<T>(value : T,  remainder: &[u8]) -> ParseResult<T> {
        Ok(ParseToken { value, remainder })
    }

    fn parse_seq(content: &[u8]) -> Result<ASNType, ParseError> {
        if content.is_empty() {
            Err(ParseError::EmptySequence)
        } else {
            Ok(ASNType::Sequence(content))
        }
    }

    fn parse_set(content: &[u8]) -> Result<ASNType, ParseError> {
        if content.is_empty() {
            Err(ParseError::EmptySet)
        } else {
            Ok(ASNType::Set(content))
        }
    }

    fn parse_null(content: &[u8]) -> Result<ASNType, ParseError> {
        if content.is_empty() {
            Ok(ASNType::Null)
        }
        else {
            Err(ParseError::NullWithNonEmptyContents(content))
        }
    }

    fn parse_integer(content: &[u8]) -> Result<ASNType, ParseError> {
        if content.is_empty() {
            Err(ParseError::ZeroLengthInteger)
        }
        else {
            Ok(ASNType::Integer(IntegerCell::new(content)))
        }
    }

    fn parse_string<T : Fn(&str) -> ASNType>(content: &[u8], create: T) -> Result<ASNType, ParseError> {
        match str::from_utf8(content) {
            Ok(x) => Ok(create(x)),
            Err(x) => Err(ParseError::BadUTF8(x))
        }
    }

    fn parse_object_identifier(content: &[u8]) -> Result<ASNType, ParseError> {

        fn parse_remainder<'a>(content: &'a[u8], items: &mut Vec<u32>) -> Result<(), ParseError<'a>> {

            fn parse_one(content: &[u8]) -> ParseResult<u32> {
                let mut sum : u32 = 0;
                let mut count: u32 = 0;
                let mut cursor = content;

                loop {

                    // only allow 4*7 = 28 bits so that we don't overflow u32
                    if count > 3 { return Err(ParseError::BadOidLength) };
                    if cursor.is_empty() { return Err(InsufficientBytes(1, cursor)) }

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

            let mut current = content;

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

        if content.is_empty() {
            return Err(ParseError::InsufficientBytes(1, content))
        }

        let first = content[0] / 40;
        let second = content[0] % 40;

        let mut items : Vec<u32> = Vec::new();

        items.push(first as u32);
        items.push(second as u32);

        parse_remainder(&content[1..], &mut items)?;

        Ok(ASNType::ObjectIdentifier(items))
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

    fn parse_one_type(input: &[u8]) -> ParseResult<ASNType> {

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
           0x03 => Ok(ASNType::GenericTLV("BitString", content)),
           0x04 => Ok(ASNType::GenericTLV("OctetString", content)),
           0x05 => parse_null(content),
           0x06 => parse_object_identifier(content),
           0x0C => parse_string(content, |s| ASNType::UTF8String(s)),
           0x13 => parse_string(content, |s| ASNType::PrintableString(s)),
           //0x14 => Ok(ASNToken::GenericTLV("T61String", content)),
           0x16 => parse_string(content, |s| ASNType::IA5String(s)),
           0x17 => Ok(ASNType::GenericTLV("UTCTime", content)),

           // structured types
           0x30 => parse_seq(content),
           0x31 => parse_set(content),

           x => Err(ParseError::UnsupportedUniversalType(x))
        };

        result.map(|value| ParseToken::new(value, &length.remainder[length.value..]))
    }

    struct Parser<'a> {
        cursor: &'a[u8]
    }

    impl<'a> Parser<'a> {
        fn new(input: &'a[u8]) -> Parser {
            Parser { cursor: input }
        }
    }


    impl<'a> Iterator for Parser<'a> {

        type Item = Result<ASNType<'a>, ParseError<'a>>;


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

    trait ParseHandler {
        fn begin_constructed(&mut self) -> ();
        fn end_constructed(&mut self) -> ();
        fn on_type(&mut self, asn: &ASNType) -> ();
        fn on_error(&mut self, err: &ParseError) -> ();
    }

    fn parse_all<'a, T : ParseHandler>(input: &'a[u8], handler: &mut T) -> Result<(), ParseError<'a>> {
        for result in Parser::new(input) {
            match result {
                Err(err) => {
                    handler.on_error(&err);
                    return Err(err)
                },
                Ok(asn) => {
                    handler.on_type(&asn);
                    match asn {
                        ASNType::Sequence(content) => {
                            handler.begin_constructed();
                            parse_all(content, handler)?;
                            handler.end_constructed();
                        }
                        ASNType::Set(content) => {
                            handler.begin_constructed();
                            parse_all(content, handler)?;
                            handler.end_constructed();
                        }
                        _ => ()
                    }
                }
            }
        }

        Ok(())
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
            assert_eq!(parse_one_type(&[0xFF]), Err(ParseError::NonUniversalType(0xFF)))
        }

        #[test]
        fn parse_one_fails_for_unknown_universal_type() {
            assert_eq!(parse_one_type(&[0x3F, 0x00]), Err(ParseError::UnsupportedUniversalType(0x3F)))
        }

        #[test]
        fn parses_sequence_correctly() {
            assert_eq!(parse_one_type(&[0x30, 0x03, 0x02, 0x03, 0x04, 0x05, 0x06]), parse_ok(ASNType::Sequence(&[0x02, 0x03, 0x04]), &[0x05, 0x06]))
        }

        #[test]
        fn parse_sequence_fails_if_insufficient_bytes() {
            assert_eq!(parse_one_type(&[0x30, 0x0F, 0xDE, 0xAD]), Err(ParseError::InsufficientBytes(0x0F, &[0xDE, 0xAD])));
        }

        #[test]
        fn parses_known_object_identifiers() {
            // Microsoft: szOID_REQUEST_CLIENT_INFO
            assert_eq!(
                parse_object_identifier(&[0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x15, 0x14]),
                Ok(ASNType::ObjectIdentifier([1,3, 6,1,4,1,311,21,20].to_vec()))
            );

            // sha1WithRSAEncryption
            assert_eq!(
                parse_object_identifier(&[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x05]),
                Ok(ASNType::ObjectIdentifier([1,2,840,113549,1,1,5].to_vec()))
            );

        }

        struct ParsePrinter {
            indent: usize
        }

        impl ParsePrinter {
            fn print_indent(&self) -> () {
                for _ in 0 .. self.indent {
                    print!("  ");
                }
            }

            fn new() -> ParsePrinter {
                ParsePrinter {indent: 0}
            }
        }

        impl ParseHandler for ParsePrinter {

            fn begin_constructed(&mut self) -> () {
                self.indent += 1;
            }

            fn end_constructed(&mut self) -> () {
                self.indent -= 1;
            }

            fn on_type(&mut self, asn: &ASNType) -> () {
                self.print_indent();
                match asn {
                    ASNType::Sequence(_) => println!("Sequence"),
                    ASNType::Set(_) => println!("Set"),
                    ASNType::UTF8String(s) => println!("UTF8String: {}", s),
                    ASNType::PrintableString(s) => println!("PrintableString: {}", s),
                    ASNType::IA5String(s) => println!("IA5String: {}", s),
                    ASNType::Integer(cell) => match cell.as_i32() {
                        Some(x) => println!("Integer: {}", x),
                        None => println!("Integer: {:?}", cell.bytes)
                    }
                    ASNType::Null => println!("Null"),
                    ASNType::ObjectIdentifier(items) => {
                        println!("ObjectIdentifier: {:?}", items);
                    }
                    ASNType::GenericTLV(name, contents) => {
                        println!("{} ({})", name, contents.len())
                    }
                }
            }

            fn on_error(&mut self, err: &ParseError) -> () {
                println!("Error: {:?}", err);
            }
        }


        #[test]
        fn iterates_over_x509() {

           // TODO - figure out why there's an additional byte at the end of the DER cert
           let (_, cert) = include_bytes!("../x509/512b-rsa-example-cert.der").split_last().unwrap();

           parse_all(cert, &mut ParsePrinter::new()).unwrap()

        }


    }
}




