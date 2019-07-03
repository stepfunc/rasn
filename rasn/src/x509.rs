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
    pub issuer : Name<'a>,
    pub validity: Validity,
    pub subject : Name<'a>,
    pub subject_public_key_info : SubjectPublicKeyInfo<'a>
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

pub struct Name<'a> {
    pub contents: &'a [u8]
}

impl<'a> Name<'a> {

    fn new(contents: &'a [u8]) -> Name<'a> {
        Name { contents}
    }

    fn parse(input: &[u8]) -> Result<Name, ASNError> {
        Ok(Name::new(input))
    }
}

pub struct SubjectPublicKeyInfo<'a> {
    pub algorithm: AlgorithmIdentifier,
    pub subject_public_key: ASNBitString<'a>
}

impl<'a> SubjectPublicKeyInfo<'a> {

    fn new(algorithm: AlgorithmIdentifier, subject_public_key: ASNBitString<'a>) -> SubjectPublicKeyInfo<'a> {
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


