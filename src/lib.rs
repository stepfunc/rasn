mod rasn {

    mod tags {

        #[derive(Debug, PartialEq)]
        pub enum IdentifierType {
            Universal,
            Application,
            ContextSpecific,
            Private
        }

        #[derive(Debug, PartialEq)]
        pub enum SimpleType {
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

        pub fn get_identifier_type(value: u8) -> IdentifierType {
            match value & 0b11000000 {
                0b01000000 => IdentifierType::Application,
                0b10000000 => IdentifierType::ContextSpecific,
                0b11000000 => IdentifierType::Private,
                _ => IdentifierType::Universal
            }
        }

        pub fn get_simple_type(value: u8) -> SimpleType {
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
    }

    #[cfg(test)]
    mod tests {
        use rasn::tags::*;

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
    }
}




