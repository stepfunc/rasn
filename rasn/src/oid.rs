use types::ASNObjectIdentifier;
use std::collections::HashMap;


pub enum AlgorithmID {
    Ed25519
}

impl AlgorithmID {
    pub fn to_str(&self) -> &str {
        match self {
            AlgorithmID::Ed25519 => "Edwards-curve Digital Signature Algorithm (EdDSA) Ed25519"
        }
    }
}

pub enum KnownOID {
    CommonName,
    OrganizationName,
    CountryName,
    StateOrProvinceName,
    Algorithm(AlgorithmID)
}

impl KnownOID {
    pub fn to_str(&self) -> &str {
        match self {
            KnownOID::CommonName => "common name",
            KnownOID::CountryName => "country name",
            KnownOID::OrganizationName => "organization name",
            KnownOID::StateOrProvinceName => "state or province name",
            KnownOID::Algorithm(id) => id.to_str()
        }
    }
}

pub fn get_oid(id : &ASNObjectIdentifier) -> Option<KnownOID> {
    match id.values() {
        [1,3,101,112] => Some(KnownOID::Algorithm(AlgorithmID::Ed25519)),
        [2,5,4,3] => Some(KnownOID::CommonName),
        [2,5,4,6] => Some(KnownOID::CountryName),
        [2,5,4,10] => Some(KnownOID::OrganizationName),
        [2,5,4,8] => Some(KnownOID::StateOrProvinceName),
        _ => None
    }
}