pub trait LinePrinter {
    fn begin_type(&mut self);

    fn begin_line(&mut self);

    fn print_fmt(&mut self, fmt: &std::fmt::Arguments);
    fn print_str(&mut self, s: &str);
    fn println_fmt(&mut self, fmt: &std::fmt::Arguments);
    fn println_str(&mut self, line: &str);

    fn end_type(&mut self);
}

pub trait Printable {
    fn print(&self, printer: &mut dyn LinePrinter);
}

pub fn print_type(name: &str, printable: &dyn Printable, printer: &mut dyn LinePrinter) {
    printer.begin_line();
    printer.println_fmt(&format_args!("{}:", name));
    printer.begin_type();
    printable.print(printer);
    printer.end_type();
}

pub struct ConsoleLinePrinter {
    indent: usize,
}

impl ConsoleLinePrinter {
    pub fn new() -> ConsoleLinePrinter {
        ConsoleLinePrinter { indent: 0 }
    }

    fn print_indent(&self) {
        for _ in 0..self.indent {
            print!("  ")
        }
    }
}

impl Default for ConsoleLinePrinter {
    fn default() -> Self {
        ConsoleLinePrinter::new()
    }
}

impl LinePrinter for ConsoleLinePrinter {
    fn begin_type(&mut self) {
        self.indent += 1;
    }

    fn begin_line(&mut self) {
        self.print_indent();
    }

    fn print_fmt(&mut self, args: &std::fmt::Arguments) {
        print!("{}", args)
    }

    fn print_str(&mut self, s: &str) {
        print!("{}", s)
    }

    fn println_fmt(&mut self, args: &std::fmt::Arguments) {
        println!("{}", args)
    }

    fn println_str(&mut self, line: &str) {
        println!("{}", line)
    }

    fn end_type(&mut self) {
        self.indent -= 1;
    }
}
