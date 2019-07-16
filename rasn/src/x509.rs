use types::{ASNBitString, ASNError, ASNInteger, ASNType, ASNObjectIdentifier};
use parser::{Parser, parse_all};
use printer::{Printable, LinePrinter, print_type};
use extensions::{Extension};

#[derive(Debug)]
pub struct Constructed<'a, T> {
    pub bytes: &'a[u8],
    pub value: T
}

impl<'a, T> Constructed<'a, T> {
    pub fn new(bytes: &'a[u8], value: T) -> Constructed<T> {
        Constructed { bytes, value}
    }
}

#[derive(Debug)]
pub struct Certificate<'a> {
    // preserve raw bytes for signature validation using Constructed<T>
    pub tbs_certificate : Constructed<'a, TBSCertificate<'a>>,
    pub signature_algorithm : AlgorithmIdentifier<'a>,
    pub signature_value : ASNBitString<'a>
}

impl<'a> Printable for Certificate<'a> {
    fn print(&self, printer: &mut LinePrinter) -> () {
        print_type("tbs certificate", &self.tbs_certificate.value, printer);
        print_type("signature algorithm", &self.signature_algorithm, printer);
        print_type("signature value", &self.signature_value, printer);
    }
}

impl<'a> Printable for &'a [u8] {
    fn print(&self, printer: &mut LinePrinter) -> () {
        for chunk in self.chunks(16) {
            printer.begin_line();
            if let Some((last, first)) = chunk.split_last() {
                for byte in first {
                    printer.print_fmt(&format_args!("{:02X}:", byte));
                }
                printer.println_fmt(&format_args!("{:02X}", last));
            }
        }
    }
}

impl<'a> Printable for ASNBitString<'a> {
    fn print(&self, printer: &mut LinePrinter) -> () {
        if let Some(octets) = self.octets() {
            octets.print(printer);
        }
    }
}

#[derive(Debug)]
pub struct AlgorithmIdentifier<'a> {
    pub algorithm : ASNObjectIdentifier,
    pub parameters : Option<ASNType<'a>>
}

impl<'a> Printable for AlgorithmIdentifier<'a> {
    fn print(&self, printer: &mut LinePrinter) -> () {
        printer.begin_line();
        printer.println_fmt(&format_args!("algorithm: {}", self.algorithm));
    }
}

#[derive(Debug)]
pub enum Version {
    V1,
    V2,
    V3
}

#[derive(Debug)]
pub struct TBSCertificate<'a> {
    pub version : Version,
    pub serial_number : ASNInteger<'a>,
    pub signature : AlgorithmIdentifier<'a>,
    pub issuer : Name<'a>,
    pub validity: Validity,
    pub subject : Name<'a>,
    pub subject_public_key_info : SubjectPublicKeyInfo<'a>,
    pub issuer_unique_id : Option<ASNBitString<'a>>,
    pub subject_unique_id : Option<ASNBitString<'a>>,
    pub extensions : Vec<Extension<'a>>,
}

impl<'a> Printable for TBSCertificate<'a> {
    fn print(&self, printer: &mut LinePrinter) -> () {

        printer.begin_line();
        printer.println_fmt(&format_args!("version: {:?}", self.version));

        printer.begin_line();
        printer.println_fmt(&format_args!("serial number: {}", self.serial_number));

        print_type("signature", &self.signature, printer);
        print_type("issuer", &self.issuer, printer);
        print_type("validity", &self.validity, printer);
        print_type("subject", &self.subject, printer);
        print_type("subject public key info", &self.subject_public_key_info, printer);
        if let Some(issuer_unique_id) = &self.issuer_unique_id { print_type("issuer unique ID", issuer_unique_id, printer); }
        if let Some(subject_unique_id) = &self.subject_unique_id { print_type("subject unique ID", subject_unique_id, printer); }

        if !self.extensions.is_empty() {
            printer.begin_line();
            printer.println_str("Extensions");

            printer.begin_type();
            for extension in &self.extensions {
                extension.print(printer);
            }
            printer.end_type();
        }

    }
}

type Time = chrono::DateTime<chrono::FixedOffset>;

#[derive(Debug)]
pub struct Validity {
    pub not_before : Time,
    pub not_after : Time
}

impl Validity {
    fn new(not_before : Time, not_after : Time) -> Validity {
        Validity { not_before, not_after }
    }

    fn parse(input: &[u8]) -> Result<Validity, ASNError> {

        parse_all(input, |parser| {
            Ok(Validity::new( parser.expect_utc_time()?,  parser.expect_utc_time()?))
        })

    }
}

impl Printable for Validity {
    fn print(&self, printer: &mut LinePrinter) -> () {

        printer.begin_line();
        printer.println_fmt(&format_args!("not before: {}", self.not_before));

        printer.begin_line();
        printer.println_fmt(&format_args!("not after: {}", self.not_after));
    }
}

#[derive(Debug)]
pub struct AttributeTypeAndValue<'a> {
    pub id : ASNObjectIdentifier,
    pub value : ASNType<'a>
}

impl<'a> AttributeTypeAndValue<'a> {

    fn new(id : ASNObjectIdentifier, value : ASNType<'a>) -> AttributeTypeAndValue<'a> {
        AttributeTypeAndValue { id, value}
    }

    fn parse(input: &'a [u8]) -> Result<AttributeTypeAndValue<'a>, ASNError> {
        let mut parser = Parser::new(input);

        let value = AttributeTypeAndValue::new( parser.expect_object_identifier()?,  parser.expect_any()?);

        parser.expect_end()?;

        Ok(value)
    }
}

impl<'a> Printable for AttributeTypeAndValue<'a> {
    fn print(&self, printer: &mut LinePrinter) -> () {
        printer.begin_line();
        printer.println_fmt(&format_args!("id: {}", self.id));
        printer.begin_line();
        printer.println_fmt(&format_args!("{}", self.value));
    }
}

#[derive(Debug)]
pub struct RelativeDistinguishedName<'a> {
    values : Vec<AttributeTypeAndValue<'a>>
}

impl<'a> RelativeDistinguishedName<'a> {

    fn new(values: Vec<AttributeTypeAndValue<'a>>) -> RelativeDistinguishedName<'a> {
        RelativeDistinguishedName { values }
    }

    fn parse(input: &'a [u8]) -> Result<RelativeDistinguishedName<'a>, ASNError> {

        let mut parser = Parser::new(input);

        let mut entries : Vec<AttributeTypeAndValue> = Vec::new();

        // expect at least one entry!
        entries.push(AttributeTypeAndValue::parse(parser.expect_sequence()?)?);

        while !parser.is_empty() {
            entries.push(AttributeTypeAndValue::parse(parser.expect_sequence()?)?);
        }

        Ok(RelativeDistinguishedName::new(entries))
    }
}

#[derive(Debug)]
pub struct Name<'a> {
    pub values: Vec<RelativeDistinguishedName<'a>>
}

impl<'a> Name<'a> {
    fn new(values: Vec<RelativeDistinguishedName<'a>>) -> Name<'a> {
        Name { values }
    }

    fn parse(input: &[u8]) -> Result<Name, ASNError> {

        let mut parser = Parser::new(input);

        let mut values : Vec<RelativeDistinguishedName> = Vec::new();

        while !parser.is_empty() {
            values.push( RelativeDistinguishedName::parse(parser.expect_set()?)?);
        }

        Ok(Name::new(values))
    }
}

impl<'a> Printable for Name<'a> {
    fn print(&self, printer: &mut LinePrinter) -> () {
        for rdn in &self.values {
            for attr in &rdn.values {
                printer.begin_type();
                attr.print(printer);
                printer.end_type();
            }
        }
    }
}

#[derive(Debug)]
pub struct SubjectPublicKeyInfo<'a> {
    pub algorithm: AlgorithmIdentifier<'a>,
    pub subject_public_key: ASNBitString<'a>
}

impl<'a> SubjectPublicKeyInfo<'a> {

    fn new(algorithm: AlgorithmIdentifier<'a>, subject_public_key: ASNBitString<'a>) -> SubjectPublicKeyInfo<'a> {
        SubjectPublicKeyInfo { algorithm, subject_public_key}
    }

    fn parse(input: &[u8]) -> Result<SubjectPublicKeyInfo, ASNError> {
        let mut parser = Parser::new(input);

        let value = SubjectPublicKeyInfo::new(
            AlgorithmIdentifier::parse(parser.expect_sequence()?)?,
            parser.expect_bit_string()?
        );

        parser.expect_end()?;

        Ok(value)
    }
}

impl<'a> Printable for SubjectPublicKeyInfo<'a> {
    fn print(&self, printer: &mut LinePrinter) -> () {
        print_type("algorithm", &self.algorithm, printer);
        print_type("subject public key", &self.subject_public_key, printer);
    }
}

impl<'a> Certificate<'a> {

    pub fn parse(input: &[u8]) -> Result<Certificate, ASNError> {
        let mut parser = Parser::unwrap_outer_sequence(input)?;

        let value = Certificate::new(
            TBSCertificate::parse(parser.expect_sequence()?)?,
            AlgorithmIdentifier::parse(parser.expect_sequence()?)?,
            parser.expect_bit_string()?
        );

        parser.expect_end()?;

        Ok(value)
    }

    pub fn new(tbs_certificate : Constructed<'a, TBSCertificate<'a>>,
           signature_algorithm : AlgorithmIdentifier<'a>,
           signature_value : ASNBitString<'a>) -> Certificate<'a> {

        Certificate { tbs_certificate, signature_algorithm, signature_value }
    }

}

impl<'a> AlgorithmIdentifier<'a> {

    fn parse(input: &[u8]) -> Result<AlgorithmIdentifier, ASNError> {

        let mut parser = Parser::new(input);

        Ok(AlgorithmIdentifier::new(parser.expect_object_identifier()?, parser.expect_any_or_end()?))
    }

    pub fn new(algorithm : ASNObjectIdentifier, parameters : Option<ASNType>) -> AlgorithmIdentifier {
        AlgorithmIdentifier { algorithm, parameters }
    }

}


impl<'a> TBSCertificate<'a> {

    pub fn new(version : Version,
               serial_number : ASNInteger<'a>,
               signature : AlgorithmIdentifier<'a>,
               issuer : Name<'a>,
               validity: Validity,
               subject : Name<'a>,
               subject_public_key_info : SubjectPublicKeyInfo<'a>,
               issuer_unique_id : Option<ASNBitString<'a>>,
               subject_unique_id : Option<ASNBitString<'a>>,
               extensions : Vec<Extension<'a>>) -> TBSCertificate<'a> {
        TBSCertificate { version, serial_number, signature, issuer, validity, subject, subject_public_key_info, issuer_unique_id, subject_unique_id, extensions }
    }

    fn parse(input: &[u8]) -> Result<Constructed<TBSCertificate>, ASNError> {

        fn parse_version(parser: &mut Parser) -> Result<Version, ASNError> {
            match parser.get_explicitly_tagged_integer_or_default(0, 0)? {
                0 => Ok(Version::V1),
                1 => Ok(Version::V2),
                2 => Ok(Version::V3),
                x => Err(ASNError::BadEnumValue("version", x))
            }
        }

        fn parse_optional_bitstring<'a>(parser: &mut Parser<'a>, tag: u8) -> Result<Option<ASNBitString<'a>>, ASNError> {
            // TODO: check minimum version
            match parser.get_optional_explicit_tag(tag)? {
                Some(tag) => {
                    let mut parser = Parser::new(tag.contents);
                    let value = parser.expect_bit_string()?;
                    parser.expect_end()?;
                    Ok(Some(value))
                }
                None => Ok(None)
            }
        }

        fn parse_extensions<'a>(parser: &mut Parser<'a>) -> Result<Vec<Extension<'a>>, ASNError> {
            // TODO: check minimum version
            let mut extensions: Vec<Extension> = Vec::new();
            match parser.get_optional_explicit_tag(3)? {
                Some(tag) => {
                    let mut parser = Parser::unwrap_outer_sequence(tag.contents)?;
                    while let Some(seq) = parser.expect_sequence_or_end()? {
                        extensions.push(Extension::parse(seq)?);
                    }
                }
                None => {}
            };
            Ok(extensions)
        }

        let mut parser = Parser::new(input);

        let value = Constructed::new(
            input,
            TBSCertificate::new(
                parse_version(&mut parser)?,
                parser.expect_integer()?,
                AlgorithmIdentifier::parse(parser.expect_sequence()?)?,
                Name::parse(parser.expect_sequence()?)?,
                Validity::parse(parser.expect_sequence()?)?,
                Name::parse(parser.expect_sequence()?)?,
                SubjectPublicKeyInfo::parse(parser.expect_sequence()?)?,
                parse_optional_bitstring(&mut parser, 1)?,
                parse_optional_bitstring(&mut parser, 2)?,
                parse_extensions(&mut parser)?,
            )
        );

        parser.expect_end()?;


        Ok(value)
    }
}


