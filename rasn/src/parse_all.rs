use types::{ASNType, ASNError};
use parser::Parser;

pub trait ParseHandler {
    fn begin_constructed(&mut self) -> ();
    fn end_constructed(&mut self) -> ();
    fn on_type(&mut self, asn: &ASNType) -> ();
    fn on_error(&mut self, err: &ASNError) -> ();
}

pub fn parse_all<'a, T : ParseHandler>(input: &'a[u8], handler: &mut T) -> Result<(), ASNError<'a>> {
    for result in Parser::new(input) {
        match result {
            Err(err) => {
                handler.on_error(&err);
                return Err(err)
            },
            Ok(asn) => {
                handler.on_type(&asn);
                match asn {
                    ASNType::Sequence(content) => {
                        handler.begin_constructed();
                        parse_all(content, handler)?;
                        handler.end_constructed();
                    }
                    ASNType::Set(content) => {
                        handler.begin_constructed();
                        parse_all(content, handler)?;
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

    struct ParsePrinter {
        indent: usize
    }

    impl ParsePrinter {
        fn print_indent(&self) -> () {
            for _ in 0..self.indent {
                print!("  ");
            }
        }

        fn new() -> ParsePrinter {
            ParsePrinter { indent: 0 }
        }
    }

    impl ParseHandler for ParsePrinter {
        fn begin_constructed(&mut self) -> () {
            self.indent += 1;
        }

        fn end_constructed(&mut self) -> () {
            self.indent -= 1;
        }

        fn on_type(&mut self, asn: &ASNType) -> () {
            self.print_indent();
            println!("{}", asn);
            match asn {
                ASNType::BitString(cell) => {
                    match cell.octets() {
                        Some(octets) => {
                            self.indent += 1;
                            for chunk in octets.chunks(16) {
                                self.print_indent();
                                match chunk.split_last() {
                                    Some((last, first)) => {
                                        for byte in first {
                                            print!("{:02X}:", byte)
                                        }
                                        println!("{:02X}", last)
                                    }
                                    None => {}
                                }
                            }
                            self.indent -= 1;
                        }
                        None => ()
                    }
                }
                _ => ()
            }
        }

        fn on_error(&mut self, err: &ASNError) -> () {
            println!("Error: {:?}", err);
        }
    }


    #[test]
    fn iterates_over_x509() {

        // TODO - figure out why there's an additional byte at the end of the DER cert
        let cert = include_bytes!("../../x509/512b-rsa-example-cert.der");

        parse_all(cert, &mut ParsePrinter::new()).unwrap()
    }


}