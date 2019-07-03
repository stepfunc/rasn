extern crate rasn;

use std::env;
use std::process;
use std::io::prelude::*;
use std::fs::File;

use rasn::types::{ASNType, ASNError};
use rasn::parse_all::{ParseHandler, parse_all};
use rasn::x509::Certificate;

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

fn get_bytes(file: &String) -> Result<Vec<u8>, std::io::Error> {
    let mut f = File::open(file)?;
    let mut vec : Vec<u8> = Vec::new();
    f.read_to_end(&mut vec)?;
    Ok(vec)
}

pub fn main() -> Result<(), std::io::Error> {

    fn parse_der(bytes: &[u8]) -> Result<(), std::io::Error> {
        parse_all(bytes, &mut ParsePrinter::new()).or_else( |err| {
            eprintln!("Error: {}", err);
            Ok(())
        })
    }

    fn parse_x509(bytes: &[u8]) -> Result<(), std::io::Error> {
        match Certificate::parse(bytes) {
            Ok(cert) => {
                println!("not before: {}", cert.tbs_certificate.value.validity.not_before);
                println!("not after: {}", cert.tbs_certificate.value.validity.not_after);
            }
            Err(err) => {
                eprintln!("Error: {}", err);
            }
        };

        Ok(())
    }

    let args: Vec<String> = env::args().collect();

    if args.len() != 3 {
        eprintln!("requires exactly 2 arguments: decoder <--der | --x509> <filename>");
        process::exit(-1);
    }

    match &*args[1] {
        "--der" => parse_der(&get_bytes(&args[2])?),
        "--x509" => parse_x509(&get_bytes(&args[2])?),
        unknown => {
            eprintln!("Unknown flag: {}", unknown);
            process::exit(-1);
        }
    }
}