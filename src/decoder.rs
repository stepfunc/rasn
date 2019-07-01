extern crate rasn;

use std::env;
use std::process;
use std::io::prelude::*;
use std::fs::File;

use rasn::types::{ASNType, ASNError};
use rasn::parse_all::{ParseHandler, parse_all};

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

pub fn main() -> Result<(), std::io::Error>{

    let args: Vec<String> = env::args().collect();

    if args.len() != 2 {
        eprintln!("requires exactly one argument!");
        process::exit(-1);
    }

    let mut f = File::open(&args[1])?;

    let mut buffer : [u8; 1024] = [0; 1024];

    let count : usize = f.read(&mut buffer)?;

    parse_all(&buffer[count..], &mut ParsePrinter::new()).unwrap();

    Ok(())
}