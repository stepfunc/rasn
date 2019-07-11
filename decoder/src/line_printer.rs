use rasn::x509::LinePrinter;

pub struct ConsoleLinePrinter {
    indent : usize
}

impl ConsoleLinePrinter {
    pub fn new() -> ConsoleLinePrinter {
        ConsoleLinePrinter { indent : 0 }
    }

    fn print_indent(&self) {
        for _ in 0 .. self.indent {
            print!("  ")
        }
    }
}

impl LinePrinter for ConsoleLinePrinter {

    fn begin_type(&mut self) -> () {
        self.indent += 1;
    }

    fn println_fmt(&mut self, args: &std::fmt::Arguments) -> () {
        self.print_indent();
        println!("{}", args)
    }

    fn println_str(&mut self, line: &str) -> () {
        self.print_indent();
        println!("{}", line)
    }

    fn end_type(&mut self) -> () {
        self.indent -= 1;
    }
}