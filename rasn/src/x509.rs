use types::{ASNBitString, ASNError, ASNInteger, ASNType, ASNObjectIdentifier};
use parser::Parser;

pub trait LinePrinter {

    fn begin_type(&mut self) -> ();
    fn println(&mut self, line : &String) -> ();
    fn println_str(&mut self, line : &str) -> ();
    fn end_type(&mut self) -> ();
}

pub trait Printable<T : LinePrinter> {
    fn print(&self, printer: &mut T) -> ();
}

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

impl<'a, T : LinePrinter> Printable<T> for Certificate<'a> {
    fn print(&self, printer: &mut T) -> () {
        printer.println_str("tbs certificate:");
        printer.begin_type();

        printer.end_type();

        printer.println_str("signature algorithm:");
        printer.begin_type();
        self.signature_algorithm.print(printer);
        printer.end_type();

        printer.println_str("signature value:");
        printer.begin_type();

        printer.end_type();
    }
}

#[derive(Debug)]
pub struct AlgorithmIdentifier<'a> {
    pub algorithm : ASNObjectIdentifier,
    pub parameters : Option<ASNType<'a>>
}

impl<'a, T : LinePrinter> Printable<T> for AlgorithmIdentifier<'a> {
    fn print(&self, printer: &mut T) -> () {
        printer.println(&format!("algorithm: {}", self.algorithm));
    }
}

#[derive(Debug)]
pub struct TBSCertificate<'a> {
    pub serial_number : ASNInteger<'a>,
    pub signature : AlgorithmIdentifier<'a>,
    pub issuer : Name<'a>,
    pub validity: Validity,
    pub subject : Name<'a>,
    pub subject_public_key_info : SubjectPublicKeyInfo<'a>
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
        let mut parser = Parser::new(input);
        let value = Validity::new( parser.expect_utc_time()?,  parser.expect_utc_time()?);
        parser.expect_end()?;
        Ok(value)
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

        let value = AttributeTypeAndValue::new(
            parser.expect_object_identifier()?,
              parser.expect_any()?
        );

        parser.expect_end()?;

        Ok(value)
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

    pub fn new(serial_number : ASNInteger<'a>,
               signature : AlgorithmIdentifier<'a>,
               issuer : Name<'a>,
               validity: Validity,
               subject : Name<'a>,
               subject_public_key_info : SubjectPublicKeyInfo<'a>) -> TBSCertificate<'a> {
        TBSCertificate { serial_number, signature, issuer, validity, subject, subject_public_key_info }
    }

    fn parse(input: &[u8]) -> Result<Constructed<TBSCertificate>, ASNError> {

        let mut parser = Parser::new(input);

        let value = Constructed::new(
            input,
            TBSCertificate::new(
                parser.expect_integer()?,
                AlgorithmIdentifier::parse(parser.expect_sequence()?)?,
                Name::parse(parser.expect_sequence()?)?,
                Validity::parse(parser.expect_sequence()?)?,
                Name::parse(parser.expect_sequence()?)?,
                SubjectPublicKeyInfo::parse(parser.expect_sequence()?)?
            )
        );

        // TODO - handle optional fields!

        parser.expect_end()?;


        Ok(value)
    }
}


