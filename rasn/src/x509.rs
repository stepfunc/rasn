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

        let not_before = parser.expect_utc_time()?;
        let not_after = parser.expect_utc_time()?;

        parser.expect_end()?;

        Ok(Validity::new(not_before, not_after))
    }
}

impl<'a> Certificate<'a> {

    pub fn parse(input: &[u8]) -> Result<Certificate, ASNError> {
        let mut parser = Parser::unwrap_outer_sequence(input)?;

        let tbs_certificate = TBSCertificate::parse(parser.expect_sequence()?)?;
        let signature_algorithm : AlgorithmIdentifier = AlgorithmIdentifier::parse(parser.expect_sequence()?)?;
        let signature_value = parser.expect_bit_string()?;

        parser.expect_end()?;

        Ok(Certificate::new(tbs_certificate, signature_algorithm, signature_value))
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
        let algorithm = parser.expect_object_identifier()?;

        // TODO - identify the algorithm

        parser.expect_end()?;

        Ok(AlgorithmIdentifier::new(algorithm, None))
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

        let serial_number = parser.expect_integer()?;

        let signature = AlgorithmIdentifier::parse(parser.expect_sequence()?)?;
        let issuer = parser.expect_sequence()?;
        let validity = Validity::parse(parser.expect_sequence()?)?;

        // TODO
        // parser.expect_end()?;

        Ok(
            Constructed::new(
                input,
                TBSCertificate::new(serial_number, signature, issuer, validity)
            )
        )
    }
}


