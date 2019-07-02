use types::{ASNBitString, ASNObjectIdentifier, ASNError};
use parser::Parser;

pub struct Certificate<'a> {
    pub tbs_certificate : TBSCertificate,
    pub tbs_certificate_bytes : &'a[u8],             // provide the raw bytes for tbs_certificate for signature validation
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

        let tbs_certificate_bytes : &[u8] = parser.expect_sequence()?;
        let tbs_certificate = TBSCertificate::parse(tbs_certificate_bytes)?;
        let signature_algorithm : AlgorithmIdentifier = AlgorithmIdentifier::parse(parser.expect_sequence()?)?;
        let signature_value = parser.expect_bit_string()?;

        parser.expect_end()?;

        Ok(Certificate::new(tbs_certificate, tbs_certificate_bytes, signature_algorithm, signature_value))
    }

    pub fn new(tbs_certificate : TBSCertificate,
           tbs_certificate_bytes : &'a[u8],
           signature_algorithm : AlgorithmIdentifier,
           signature_value : ASNBitString<'a>) -> Certificate<'a> {

        Certificate { tbs_certificate, tbs_certificate_bytes, signature_algorithm, signature_value }
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

    fn parse(_: &[u8]) -> Result<TBSCertificate, ASNError> {
        // TODO
        Ok(TBSCertificate::new())
    }
}


