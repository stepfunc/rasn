use rasn::der::types::{ASNError, ASNType};
use rasn::der::ParseHandler;

pub struct ParsePrinter {
    indent: usize,
}

impl ParsePrinter {
    fn print_indent(&self) {
        for _ in 0..self.indent {
            print!("  ");
        }
    }

    pub fn new() -> ParsePrinter {
        ParsePrinter { indent: 0 }
    }
}

impl ParseHandler for ParsePrinter {
    fn begin_constructed(&mut self) {
        self.indent += 1;
    }

    fn end_constructed(&mut self) {
        self.indent -= 1;
    }

    fn on_type(&mut self, asn: &ASNType) {
        self.print_indent();
        println!("{}", asn);
        if let ASNType::BitString(wrapper) = asn {
            if let Some(octets) = wrapper.value.octets() {
                self.indent += 1;
                for chunk in octets.chunks(16) {
                    self.print_indent();
                    if let Some((last, first)) = chunk.split_last() {
                        for byte in first {
                            print!("{:02X}:", byte)
                        }
                        println!("{:02X}", last)
                    }
                }
                self.indent -= 1;
            }
        }
    }

    fn on_error(&mut self, err: &ASNError) {
        println!("Error: {:?}", err);
    }
}
