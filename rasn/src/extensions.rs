use types::{ASNObjectIdentifier, ASNError};
use parser::Parser;
use printer::{Printable, LinePrinter, print_type};
use std::fmt::Debug;

#[derive(Debug)]
pub struct Extension<'a> {
    pub extn_id: ASNObjectIdentifier,
    pub critical: bool,
    pub content: Box<dyn SpecificExtension + 'a>,
}

impl<'a> Extension<'a> {
    pub fn new(extn_id: ASNObjectIdentifier, critical: bool, content: Box<dyn SpecificExtension + 'a>) -> Extension<'a> {
        Extension { extn_id, critical, content }
    }

    pub fn parse(input: &'a [u8]) -> Result<Extension, ASNError> {
        let mut parser = Parser::new(input);

        let oid = parser.expect_object_identifier()?;
        let is_critical = parser.get_optional_boolean_or_default(false)?;
        let raw_content = parser.expect_octet_string()?;
        parser.expect_end()?;

        let content: Box<dyn SpecificExtension> = match oid.values() {
            [2, 5, 29, 15] => Box::new(KeyUsage::parse(raw_content)?),
            [2, 5, 29, 37] => Box::new(ExtendedKeyUsage::parse(raw_content)?),
            _ => Box::new(UnknownExtension::new(raw_content)),
        };

        Ok(Extension::new(oid, is_critical, content))
    }
}

impl<'a> Printable for Extension<'a> {
    fn print(&self, printer: &mut LinePrinter) -> () {
        printer.begin_line();
        printer.println_fmt(&format_args!("extension id: {}", self.extn_id));
        printer.begin_line();
        printer.println_fmt(&format_args!("critical: {}", self.critical));
        self.content.print(printer);
    }
}

pub trait SpecificExtension : Debug + Printable {}

#[derive(Debug)]
pub struct UnknownExtension<'a> {
    pub extn_value: &'a[u8],
}

impl<'a> SpecificExtension for UnknownExtension<'a> {}

impl<'a> UnknownExtension<'a> {
    fn new(extn_value: &'a[u8]) -> UnknownExtension<'a> {
        UnknownExtension { extn_value }
    }
}

impl<'a> Printable for UnknownExtension<'a> {
    fn print(&self, printer: &mut LinePrinter) -> () {
        print_type("extension value", &self.extn_value, printer);
    }
}

#[derive(Debug)]
pub enum ExtendedKeyUsagePurpose {
    ServerAuth,
    ClientAuth,
    CodeSigning,
    EmailProtection,
    TimeStamping,
    OCSPSigning,
}

impl ExtendedKeyUsagePurpose {
    pub fn from_id(oid: &ASNObjectIdentifier) -> Option<ExtendedKeyUsagePurpose> {
        match oid.values() {
            [1, 3, 6, 1, 5, 5, 7, 3, 1] => Some(ExtendedKeyUsagePurpose::ServerAuth),
            [1, 3, 6, 1, 5, 5, 7, 3, 2] => Some(ExtendedKeyUsagePurpose::ClientAuth),
            [1, 3, 6, 1, 5, 5, 7, 3, 3] => Some(ExtendedKeyUsagePurpose::CodeSigning),
            [1, 3, 6, 1, 5, 5, 7, 3, 4] => Some(ExtendedKeyUsagePurpose::EmailProtection),
            [1, 3, 6, 1, 5, 5, 7, 3, 8] => Some(ExtendedKeyUsagePurpose::TimeStamping),
            [1, 3, 6, 1, 5, 5, 7, 3, 9] => Some(ExtendedKeyUsagePurpose::OCSPSigning),
            _ => None
        }
    }
}

#[derive(Debug)]
pub struct ExtendedKeyUsage {
    pub ext_key_usages: Vec<ExtendedKeyUsagePurpose>,
}

impl SpecificExtension for ExtendedKeyUsage {}

impl ExtendedKeyUsage {
    fn parse(input: &[u8]) -> Result<ExtendedKeyUsage, ASNError> {
        let mut parser = Parser::unwrap_outer_sequence(input)?;
        let mut purposes: Vec<ExtendedKeyUsagePurpose> = Vec::new();

        while !parser.is_empty() {
            let oid = parser.expect_object_identifier()?;
            match ExtendedKeyUsagePurpose::from_id(&oid) {
                Some(purpose) => purposes.push(purpose),
                None => return Err(ASNError::UnexpectedOid(oid)),
            }
        };

        Ok(ExtendedKeyUsage{ ext_key_usages: purposes })
    }
}

impl Printable for ExtendedKeyUsage {
    fn print(&self, printer: &mut LinePrinter) -> () {
        printer.begin_line();
        printer.println_str("extended key usages:");
        printer.begin_type();
        for purpose in &self.ext_key_usages {
            printer.begin_line();
            printer.println_fmt(&format_args!("{:?}", purpose));
        }
        printer.end_type();
    }
}

#[derive(Debug)]
pub struct KeyUsage {
    pub digital_signature: bool,
    pub content_commitment: bool,
    pub key_encipherment: bool,
    pub data_encipherment: bool,
    pub key_agreement: bool,
    pub key_cert_sign: bool,
    pub crl_sign: bool,
    pub encipher_only: bool,
    pub decipher_only: bool,
}

impl SpecificExtension for KeyUsage {}

impl KeyUsage {
    fn parse(input: &[u8]) -> Result<KeyUsage, ASNError> {
        fn extract_bits(value: u8) -> KeyUsage {
            KeyUsage {
                digital_signature:  value & 0b00000001 != 0,
                content_commitment: value & 0b00000010 != 0,
                key_encipherment:   value & 0b00000100 != 0,
                data_encipherment:  value & 0b00001000 != 0,
                key_agreement:      value & 0b00010000 != 0,
                key_cert_sign:      value & 0b00100000 != 0,
                crl_sign:           value & 0b01000000 != 0,
                encipher_only:      value & 0b10000000 != 0,
                decipher_only: false,
            }
        }

        let mut parser = Parser::new(input);
        let bit_string = parser.expect_bit_string()?;

        let mut key_usage = KeyUsage {
            digital_signature: false,
            content_commitment: false,
            key_encipherment: false,
            data_encipherment: false,
            key_agreement: false,
            key_cert_sign: false,
            crl_sign: false,
            encipher_only: false,
            decipher_only: false,
        };
        let mut offset = 0;
        for bit in bit_string.iter() {
            match offset {
                0 => key_usage.digital_signature = bit,
                1 => key_usage.content_commitment = bit,
                2 => key_usage.key_encipherment = bit,
                3 => key_usage.data_encipherment = bit,
                4 => key_usage.key_agreement = bit,
                5 => key_usage.key_cert_sign = bit,
                6 => key_usage.crl_sign = bit,
                7 => key_usage.encipher_only = bit,
                8 => key_usage.decipher_only = bit,
                _ => {}
            }
            offset += offset;
        }
        Ok(key_usage)
    }
}

impl Printable for KeyUsage {
    fn print(&self, printer: &mut LinePrinter) -> () {
        fn print_usage(description: &str, printer: &mut LinePrinter) {
            printer.begin_type();
            printer.begin_line();
            printer.println_str(description);
            printer.end_type();
        }

        printer.begin_line();
        printer.println_str("key usages:");

        if self.digital_signature { print_usage("digital signature", printer) }
        if self.content_commitment { print_usage("content commitment", printer) }
        if self.key_encipherment { print_usage("key encipherment", printer) }
        if self.data_encipherment { print_usage("data encipherment", printer) }
        if self.key_agreement { print_usage("key agreement", printer) }
        if self.key_cert_sign { print_usage("key cert sign", printer) }
        if self.crl_sign { print_usage("crl sign", printer) }
        if self.encipher_only { print_usage("encipher only", printer) }
        if self.decipher_only { print_usage("decipher only", printer) }
    }
}
