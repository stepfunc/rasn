use crate::x509::Certificate;

#[test]
fn parses_rsa_cert() {
    Certificate::parse(include_bytes!("../../../certs/512b-rsa-example-cert.der")).unwrap();
}

#[test]
fn parses_cert_with_generalized_time() {
    Certificate::parse(include_bytes!(
        "../../../certs/cert_with_generalized_time.der"
    ))
    .unwrap();
}

#[test]
fn parses_ed25519_cert() {
    Certificate::parse(include_bytes!("../../../certs/ed25519-example-cert.der")).unwrap();
}

#[test]
fn google_root_cert() {
    Certificate::parse(include_bytes!("../../../certs/google_root_cert.cer")).unwrap();
}
