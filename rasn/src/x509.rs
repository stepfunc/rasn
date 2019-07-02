use types::{ASNBitString, ASNObjectIdentifier, ASNError};
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
    // preserve raw bytes for signature validation
    pub tbs_certificate : Constructed<'a, TBSCertificate>,
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

pub struct TBSCertificate {

}

impl<'a> Certificate<'a> {

    pub fn parse(input: &[u8]) -> Result<Certificate, ASNError> {

        let mut parser = Parser::new(input);

        let tbs_certificate = TBSCertificate::parse(parser.expect_sequence()?)?;
        let signature_algorithm : AlgorithmIdentifier = AlgorithmIdentifier::parse(parser.expect_sequence()?)?;
        let signature_value = parser.expect_bit_string()?;

        parser.expect_end()?;

        Ok(Certificate::new(tbs_certificate, signature_algorithm, signature_value))
    }

    pub fn new(tbs_certificate : Constructed<'a, TBSCertificate>,
           signature_algorithm : AlgorithmIdentifier,
           signature_value : ASNBitString<'a>) -> Certificate<'a> {

        Certificate { tbs_certificate, signature_algorithm, signature_value }
    }

}

impl AlgorithmIdentifier {

    fn parse(input: &[u8]) -> Result<AlgorithmIdentifier, ASNError> {
        let mut parser = Parser::new(input);
        let algorithm = parser.expect_object_identifier()?;
        parser.expect_end()?;
        Ok(AlgorithmIdentifier::new(algorithm, None))
    }

    pub fn new(algorithm : ASNObjectIdentifier, parameters : Option<AlgorithmParameters>) -> AlgorithmIdentifier {
        AlgorithmIdentifier { algorithm, parameters }
    }

}


impl TBSCertificate {

    pub fn new() -> TBSCertificate {
        TBSCertificate {}
    }

    fn parse(bytes: &[u8]) -> Result<Constructed<TBSCertificate>, ASNError> {
        // TODO
        Ok(Constructed::new(bytes, TBSCertificate::new()))
    }
}


