extern crate rasn;

mod der_printer;

use std::env;
use std::fs::File;
use std::io::prelude::*;
use std::process;

use rasn::parse_all::parse_all;
use rasn::printer::{ConsoleLinePrinter, Printable};
use rasn::x509::Certificate;

fn get_bytes(file: &String) -> Result<Vec<u8>, std::io::Error> {
    let mut f = File::open(file)?;
    let mut vec: Vec<u8> = Vec::new();
    f.read_to_end(&mut vec)?;
    Ok(vec)
}

pub fn main() -> Result<(), std::io::Error> {
    fn parse_der(bytes: &[u8]) -> Result<(), std::io::Error> {
        parse_all(bytes, &mut der_printer::ParsePrinter::new()).or_else(|err| {
            eprintln!("Error: {}", err);
            Ok(())
        })
    }

    fn parse_x509(bytes: &[u8]) -> Result<(), std::io::Error> {
        match Certificate::parse(bytes) {
            Ok(cert) => cert.print(&mut ConsoleLinePrinter::new()),
            Err(err) => eprintln!("Error: {}", err),
        };

        Ok(())
    }

    let args: Vec<String> = env::args().collect();

    if args.len() != 3 {
        eprintln!("requires exactly 2 arguments: decoder <--der | --x509> <filename>");
        process::exit(-1);
    }

    match args[1].as_str() {
        "--der" => parse_der(&get_bytes(&args[2])?),
        "--x509" => parse_x509(&get_bytes(&args[2])?),
        unknown => {
            eprintln!("Unknown flag: {}", unknown);
            process::exit(-1);
        }
    }
}
