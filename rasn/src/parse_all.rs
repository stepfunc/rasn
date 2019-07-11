use types::{ASNType, ASNError};
use parser::Parser;

pub trait ParseHandler {
    fn begin_constructed(&mut self) -> ();
    fn end_constructed(&mut self) -> ();
    fn on_type(&mut self, asn: &ASNType) -> ();
    fn on_error(&mut self, err: &ASNError) -> ();
}

pub fn parse_all<T : ParseHandler>(input: &[u8], handler: &mut T) -> Result<(), ASNError> {
    for result in Parser::new(input) {
        match result {
            Err(err) => {
                handler.on_error(&err);
                return Err(err)
            },
            Ok(asn) => {
                handler.on_type(&asn);
                match asn {
                    ASNType::Sequence(contents) => {
                        handler.begin_constructed();
                        parse_all(contents, handler)?;
                        handler.end_constructed();
                    }
                    ASNType::ExplicitTag(_, contents) => {
                        handler.begin_constructed();
                        parse_all(contents, handler)?;
                        handler.end_constructed();
                    }
                    ASNType::Set(contents) => {
                        handler.begin_constructed();
                        parse_all(contents, handler)?;
                        handler.end_constructed();
                    }
                    _ => ()
                }
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {

    use parse_all::{parse_all, ParseHandler};
    use types::{ASNType, ASNError};

    struct MockHandler {}

    impl ParseHandler for MockHandler {
        fn begin_constructed(&mut self) -> () {}

        fn end_constructed(&mut self) -> () {}

        fn on_type(&mut self, _: &ASNType) -> () {}

        fn on_error(&mut self, _: &ASNError) -> () {}
    }

    #[test]
    fn parses_rsa_x509_without_error() {
        // just checking that an error doesn't occur
        parse_all(include_bytes!("../../x509/512b-rsa-example-cert.der"), &mut MockHandler {}).unwrap();
    }

    #[test]
    fn parses_ed22519_x509_without_error() {
        // just checking that an error doesn't occur
        parse_all(include_bytes!("../../x509/ed25519-example-cert.der"), &mut MockHandler {}).unwrap();
    }
}