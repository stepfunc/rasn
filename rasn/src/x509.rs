use types::{ASNBitString, ASNObjectIdentifier, ASNError, ASNInteger};
use parser::Parser;

pub struct Constructed<'a, T> {
    pub bytes: &'a[u8],
    pub value: T
}

impl<'a, T> Constructed<'a, T> {
    pub fn new(bytes: &'a[u8], value: T) -> Constructed<T> {
        Constructed { bytes, value}
    }
}

pub struct Certificate<'a> {
    // preserve raw bytes for signature validation using Constructed<T>
    pub tbs_certificate : Constructed<'a, TBSCertificate<'a>>,
    pub signature_algorithm : AlgorithmIdentifier,
    pub signature_value : ASNBitString<'a>
}

pub struct AlgorithmIdentifier {
    pub algorithm : ASNObjectIdentifier,
    pub parameters : Option<AlgorithmParameters>
}

pub enum AlgorithmParameters {
    Ed25519
}

pub struct TBSCertificate<'a> {
    pub serial_number : ASNInteger<'a>,
    pub signature : AlgorithmIdentifier,
    pub issuer : &'a [u8], // punt for now and just put the struct bytes
    pub validity: Validity
}

type Time = chrono::DateTime<chrono::FixedOffset>;

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
           signature_algorithm : AlgorithmIdentifier,
           signature_value : ASNBitString<'a>) -> Certificate<'a> {

        Certificate { tbs_certificate, signature_algorithm, signature_value }
    }

}

impl AlgorithmIdentifier {

    fn parse(input: &[u8]) -> Result<AlgorithmIdentifier, ASNError> {

        let mut parser = Parser::new(input);

        let value = AlgorithmIdentifier::new(parser.expect_object_identifier()?, None);

        parser.expect_end()?;

        Ok(value)
    }

    pub fn new(algorithm : ASNObjectIdentifier, parameters : Option<AlgorithmParameters>) -> AlgorithmIdentifier {
        AlgorithmIdentifier { algorithm, parameters }
    }

}


impl<'a> TBSCertificate<'a> {

    pub fn new(serial_number : ASNInteger<'a>,
               signature : AlgorithmIdentifier,
               issuer : &'a [u8],
               validity: Validity) -> TBSCertificate<'a> {
        TBSCertificate { serial_number, signature, issuer, validity }
    }

    fn parse(input: &[u8]) -> Result<Constructed<TBSCertificate>, ASNError> {

        let mut parser = Parser::new(input);

        let tbs_certificate = Constructed::new(
            input,
            TBSCertificate::new(
                parser.expect_integer()?,
                AlgorithmIdentifier::parse(parser.expect_sequence()?)?,
                parser.expect_sequence()?,
                Validity::parse(parser.expect_sequence()?)?
            )
        );

        // TODO
        // parser.expect_end()?;

        Ok(tbs_certificate)
    }
}


