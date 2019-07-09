use rasn::parse_all::ParseHandler;
use rasn::types::{ASNType, ASNError};

pub struct ParsePrinter {
    indent: usize
}

impl ParsePrinter {
    fn print_indent(&self) -> () {
        for _ in 0..self.indent {
            print!("  ");
        }
    }

    pub fn new() -> ParsePrinter {
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