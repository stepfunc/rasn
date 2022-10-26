use crate::der::parser::Parser;
use crate::der::types::{ASNError, ASNType};

pub trait ParseHandler {
    fn begin_constructed(&mut self);
    fn end_constructed(&mut self);
    fn on_type(&mut self, asn: &ASNType);
    fn on_error(&mut self, err: &ASNError);
}

pub fn parse_all(input: &[u8], handler: &mut dyn ParseHandler) -> Result<(), ASNError> {
    for result in Parser::new(input) {
        match result {
            Err(err) => {
                let err = err.into();
                handler.on_error(&err);
                return Err(err);
            }
            Ok(asn) => {
                handler.on_type(&asn);
                match asn {
                    ASNType::Sequence(wrapper) => {
                        handler.begin_constructed();
                        parse_all(wrapper.value, handler)?;
                        handler.end_constructed();
                    }
                    ASNType::ExplicitTag(wrapper) => {
                        handler.begin_constructed();
                        parse_all(wrapper.value.contents, handler)?;
                        handler.end_constructed();
                    }
                    ASNType::Set(wrapper) => {
                        handler.begin_constructed();
                        parse_all(wrapper.value, handler)?;
                        handler.end_constructed();
                    }
                    _ => (),
                }
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockHandler {}

    impl ParseHandler for MockHandler {
        fn begin_constructed(&mut self) {}

        fn end_constructed(&mut self) {}

        fn on_type(&mut self, _: &ASNType) {}

        fn on_error(&mut self, _: &ASNError) {}
    }

    #[test]
    fn parses_rsa_x509_without_error() {
        // just checking that an error doesn't occur
        parse_all(
            include_bytes!("../../../certs/512b-rsa-example-cert.der"),
            &mut MockHandler {},
        )
        .unwrap();
    }

    #[test]
    fn parses_ed22519_x509_without_error() {
        // just checking that an error doesn't occur
        parse_all(
            include_bytes!("../../../certs/ed25519-example-cert.der"),
            &mut MockHandler {},
        )
        .unwrap();
    }
}
