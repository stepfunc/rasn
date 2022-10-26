use crate::extensions::Extensions;
use crate::parser::Parser;
use crate::printer::{print_type, LinePrinter, Printable};
use crate::types::{
    ASNBitString, ASNError, ASNErrorVariant, ASNInteger, ASNObjectIdentifier, ASNType, ASNTypeId,
    BitString, Integer, ObjectIdentifier, Sequence, Set, UtcTime,
};

#[derive(Debug)]
pub struct Constructed<'a, T> {
    pub bytes: &'a [u8],
    pub value: T,
}

impl<'a, T> Constructed<'a, T> {
    pub fn new(bytes: &'a [u8], value: T) -> Constructed<T> {
        Constructed { bytes, value }
    }
}

#[derive(Debug)]
pub struct Certificate<'a> {
    // preserve raw bytes for signature validation using Constructed<T>
    pub tbs_certificate: Constructed<'a, TBSCertificate<'a>>,
    pub signature_algorithm: AlgorithmIdentifier<'a>,
    pub signature_value: ASNBitString<'a>,
}

impl<'a> Printable for Certificate<'a> {
    fn print(&self, printer: &mut dyn LinePrinter) {
        print_type("tbs certificate", &self.tbs_certificate.value, printer);
        print_type("signature algorithm", &self.signature_algorithm, printer);
        print_type("signature value", &self.signature_value, printer);
    }
}

impl<'a> Printable for &'a [u8] {
    fn print(&self, printer: &mut dyn LinePrinter) {
        for chunk in self.chunks(16) {
            printer.begin_line();
            if let Some((last, first)) = chunk.split_last() {
                for byte in first {
                    printer.print_fmt(&format_args!("{:02X}:", byte));
                }
                printer.println_fmt(&format_args!("{:02X}", last));
            }
        }
    }
}

impl<'a> Printable for ASNBitString<'a> {
    fn print(&self, printer: &mut dyn LinePrinter) {
        if let Some(octets) = self.octets() {
            octets.print(printer);
        }
    }
}

#[derive(Debug)]
pub struct AlgorithmIdentifier<'a> {
    pub algorithm: ASNObjectIdentifier,
    pub parameters: Option<ASNType<'a>>,
}

impl<'a> Printable for AlgorithmIdentifier<'a> {
    fn print(&self, printer: &mut dyn LinePrinter) {
        printer.begin_line();
        printer.println_fmt(&format_args!("algorithm: {}", self.algorithm));
    }
}

#[derive(Debug)]
pub enum Version {
    V1,
    V2,
    V3,
}

#[derive(Debug)]
pub struct TBSCertificate<'a> {
    pub version: Version,
    pub serial_number: ASNInteger<'a>,
    pub signature: AlgorithmIdentifier<'a>,
    pub issuer: Name<'a>,
    pub validity: Validity,
    pub subject: Name<'a>,
    pub subject_public_key_info: SubjectPublicKeyInfo<'a>,
    pub issuer_unique_id: Option<ASNBitString<'a>>,
    pub subject_unique_id: Option<ASNBitString<'a>>,
    pub extensions: Option<Extensions<'a>>,
}

impl<'a> Printable for TBSCertificate<'a> {
    fn print(&self, printer: &mut dyn LinePrinter) {
        printer.begin_line();
        printer.println_fmt(&format_args!("version: {:?}", self.version));

        printer.begin_line();
        printer.println_fmt(&format_args!("serial number: {}", self.serial_number));

        print_type("signature", &self.signature, printer);

        if let Ok(result) = self.issuer.parse() {
            print_type("issuer", &result, printer);
        } else {
            print_type("issuer (raw)", &self.issuer, printer);
        }

        print_type("validity", &self.validity, printer);

        if let Ok(result) = self.subject.parse() {
            print_type("subject", &result, printer);
        } else {
            print_type("subject (raw)", &self.subject, printer);
        }

        print_type(
            "subject public key info",
            &self.subject_public_key_info,
            printer,
        );
        if let Some(issuer_unique_id) = &self.issuer_unique_id {
            print_type("issuer unique ID", issuer_unique_id, printer);
        }
        if let Some(subject_unique_id) = &self.subject_unique_id {
            print_type("subject unique ID", subject_unique_id, printer);
        }

        if let Some(extensions) = &self.extensions {
            match extensions.parse() {
                Ok(extensions) => {
                    if !extensions.is_empty() {
                        printer.begin_line();
                        printer.println_str("Extensions");

                        printer.begin_type();
                        for extension in &extensions {
                            extension.print(printer);
                        }
                        printer.end_type();
                    }
                }
                Err(err) => {
                    printer.println_fmt(&format_args!("**Error** parsing extensions: {}", err));
                }
            }
        }
    }
}

#[derive(Debug)]
pub struct Validity {
    pub not_before: UtcTime,
    pub not_after: UtcTime,
}

impl Validity {
    fn new(not_before: UtcTime, not_after: UtcTime) -> Validity {
        Validity {
            not_before,
            not_after,
        }
    }

    fn parse(input: &[u8]) -> Result<Validity, ASNErrorVariant> {
        Parser::parse_all(input, |parser| {
            Ok(Validity::new(
                parser.expect::<UtcTime>()?,
                parser.expect::<UtcTime>()?,
            ))
        })
    }

    pub fn is_valid(&self, now: UtcTime) -> bool {
        now >= self.not_before && now <= self.not_after
    }
}

impl Printable for Validity {
    fn print(&self, printer: &mut dyn LinePrinter) {
        printer.begin_line();
        printer.println_fmt(&format_args!("not before: {}", self.not_before.value));

        printer.begin_line();
        printer.println_fmt(&format_args!("not after: {}", self.not_after.value));
    }
}

pub struct RelativeDistinguishedName<'a> {
    pub country_name: Option<&'a str>,
    pub state_or_province_unit_name: Option<&'a str>,
    pub locality_name: Option<&'a str>,
    pub organization: Option<&'a str>,
    pub organizational_unit_name: Option<&'a str>,
    pub common_name: Option<&'a str>,
}

impl<'a> RelativeDistinguishedName<'a> {
    fn empty() -> Self {
        Self {
            country_name: None,
            state_or_province_unit_name: None,
            locality_name: None,
            organization: None,
            organizational_unit_name: None,
            common_name: None,
        }
    }

    fn parse(input: &'a [u8]) -> Result<Self, ASNErrorVariant> {
        let mut result = Self::empty();
        let mut parser = Parser::new(input);

        // Iterate on the RDNSequence (the only choice of Name)
        while let Some(set) = parser.expect_or_end::<Set>()? {
            let mut parser = Parser::new(set);

            // Parse the RelativeDistinguishedName
            // expect at least one entry!
            result.parse_single(parser.expect::<Sequence>()?)?;
            while let Some(seq) = parser.expect_or_end::<Sequence>()? {
                result.parse_single(seq)?;
            }
        }

        Ok(result)
    }

    fn parse_single(&mut self, input: &'a [u8]) -> Result<(), ASNErrorVariant> {
        fn fill_name_component<'b>(
            value: &ASNType<'b>,
            component: &mut Option<&'b str>,
            oid: &ASNObjectIdentifier,
        ) -> Result<(), ASNErrorVariant> {
            let str_value = match &value {
                ASNType::IA5String(value) => value.value,
                ASNType::PrintableString(value) => value.value,
                ASNType::UTF8String(value) => value.value,
                _ => {
                    return Err(ASNErrorVariant::UnexpectedType(
                        ASNTypeId::PrintableString,
                        value.get_id(),
                    ))
                }
            };

            // We only accept a single instance of each AVA type
            match component {
                Some(_) => Err(ASNErrorVariant::UnexpectedOid(oid.clone())),
                None => {
                    *component = Some(str_value);
                    Ok(())
                }
            }
        }

        Parser::parse_all(input, |parser| {
            let oid = parser.expect::<ObjectIdentifier>()?;
            let value = parser.expect_any()?;

            match oid.values() {
                [2, 5, 4, 3] => fill_name_component(&value, &mut self.common_name, &oid),
                [2, 5, 4, 6] => fill_name_component(&value, &mut self.country_name, &oid),
                [2, 5, 4, 7] => fill_name_component(&value, &mut self.locality_name, &oid),
                [2, 5, 4, 8] => {
                    fill_name_component(&value, &mut self.state_or_province_unit_name, &oid)
                }
                [2, 5, 4, 10] => fill_name_component(&value, &mut self.organization, &oid),
                [2, 5, 4, 11] => {
                    fill_name_component(&value, &mut self.organizational_unit_name, &oid)
                }
                _ => Ok(()), // ignore the AVAs we don't recognize
            }
        })
    }
}

impl<'a> Printable for RelativeDistinguishedName<'a> {
    fn print(&self, printer: &mut dyn LinePrinter) {
        if let Some(value) = self.country_name {
            printer.begin_line();
            printer.println_fmt(&format_args!("C: {}", value));
        }
        if let Some(value) = self.state_or_province_unit_name {
            printer.begin_line();
            printer.println_fmt(&format_args!("ST: {}", value));
        }
        if let Some(value) = self.locality_name {
            printer.begin_line();
            printer.println_fmt(&format_args!("L: {}", value));
        }
        if let Some(value) = self.organization {
            printer.begin_line();
            printer.println_fmt(&format_args!("O: {}", value));
        }
        if let Some(value) = self.organizational_unit_name {
            printer.begin_line();
            printer.println_fmt(&format_args!("OU: {}", value));
        }
        if let Some(value) = self.common_name {
            printer.begin_line();
            printer.println_fmt(&format_args!("CN: {}", value));
        }
    }
}

#[derive(Debug)]
pub struct Name<'a> {
    pub inner: &'a [u8],
}

impl<'a> Name<'a> {
    fn new(input: &'a [u8]) -> Self {
        Self { inner: input }
    }

    pub(crate) fn parse(&self) -> Result<RelativeDistinguishedName, ASNErrorVariant> {
        RelativeDistinguishedName::parse(self.inner)
    }
}

impl<'a> Printable for Name<'a> {
    fn print(&self, printer: &mut dyn LinePrinter) {
        printer.begin_type();
        self.inner.print(printer);
        printer.end_type();
    }
}

#[derive(Debug)]
pub struct SubjectPublicKeyInfo<'a> {
    pub algorithm: AlgorithmIdentifier<'a>,
    pub subject_public_key: ASNBitString<'a>,
}

impl<'a> SubjectPublicKeyInfo<'a> {
    fn new(
        algorithm: AlgorithmIdentifier<'a>,
        subject_public_key: ASNBitString<'a>,
    ) -> SubjectPublicKeyInfo<'a> {
        SubjectPublicKeyInfo {
            algorithm,
            subject_public_key,
        }
    }

    fn parse(input: &[u8]) -> Result<SubjectPublicKeyInfo, ASNErrorVariant> {
        Parser::parse_all(input, |parser| {
            Ok(SubjectPublicKeyInfo::new(
                AlgorithmIdentifier::parse(parser.expect::<Sequence>()?)?,
                parser.expect::<BitString>()?,
            ))
        })
    }
}

impl<'a> Printable for SubjectPublicKeyInfo<'a> {
    fn print(&self, printer: &mut dyn LinePrinter) {
        print_type("algorithm", &self.algorithm, printer);
        print_type("subject public key", &self.subject_public_key, printer);
    }
}

impl<'a> Certificate<'a> {
    pub fn parse(input: &[u8]) -> Result<Certificate, ASNError> {
        let ret = Parser::parse_all(input, |p1| {
            Parser::parse_all(p1.expect::<Sequence>()?, |p2| {
                Ok(Certificate::new(
                    TBSCertificate::parse(p2.expect::<Sequence>()?)?,
                    AlgorithmIdentifier::parse(p2.expect::<Sequence>()?)?,
                    p2.expect::<BitString>()?,
                ))
            })
        })?;
        Ok(ret)
    }

    pub(crate) fn new(
        tbs_certificate: Constructed<'a, TBSCertificate<'a>>,
        signature_algorithm: AlgorithmIdentifier<'a>,
        signature_value: ASNBitString<'a>,
    ) -> Certificate<'a> {
        Certificate {
            tbs_certificate,
            signature_algorithm,
            signature_value,
        }
    }
}

impl<'a> AlgorithmIdentifier<'a> {
    fn parse(input: &[u8]) -> Result<AlgorithmIdentifier, ASNErrorVariant> {
        let mut parser = Parser::new(input);

        Ok(AlgorithmIdentifier::new(
            parser.expect::<ObjectIdentifier>()?,
            parser.expect_any_or_end()?,
        ))
    }

    pub fn new(algorithm: ASNObjectIdentifier, parameters: Option<ASNType>) -> AlgorithmIdentifier {
        AlgorithmIdentifier {
            algorithm,
            parameters,
        }
    }
}

impl<'a> TBSCertificate<'a> {
    // certificate really has this many fields, don't warn on lint
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        version: Version,
        serial_number: ASNInteger<'a>,
        signature: AlgorithmIdentifier<'a>,
        issuer: Name<'a>,
        validity: Validity,
        subject: Name<'a>,
        subject_public_key_info: SubjectPublicKeyInfo<'a>,
        issuer_unique_id: Option<ASNBitString<'a>>,
        subject_unique_id: Option<ASNBitString<'a>>,
        extensions: Option<Extensions<'a>>,
    ) -> TBSCertificate<'a> {
        TBSCertificate {
            version,
            serial_number,
            signature,
            issuer,
            validity,
            subject,
            subject_public_key_info,
            issuer_unique_id,
            subject_unique_id,
            extensions,
        }
    }

    fn parse(input: &[u8]) -> Result<Constructed<TBSCertificate>, ASNErrorVariant> {
        fn parse_version(parser: &mut Parser) -> Result<Version, ASNErrorVariant> {
            match parser.get_optional_explicit_tag_value::<Integer>(0)? {
                Some(value) => match value.as_i32() {
                    Some(0) => Ok(Version::V1),
                    Some(1) => Ok(Version::V2),
                    Some(2) => Ok(Version::V3),
                    Some(x) => Err(ASNErrorVariant::BadEnumValue("version", x)),
                    None => Err(ASNErrorVariant::IntegerTooLarge(value.bytes.len())),
                },
                None => Ok(Version::V1),
            }
        }

        fn parse_optional_bitstring<'a>(
            parser: &mut Parser<'a>,
            tag: u8,
        ) -> Result<Option<ASNBitString<'a>>, ASNErrorVariant> {
            // TODO: check minimum version
            match parser.get_optional_explicit_tag(tag)? {
                Some(tag) => Parser::parse_all(tag.contents, |parser| {
                    Ok(Some(parser.expect::<BitString>()?))
                }),
                None => Ok(None),
            }
        }

        fn parse_extensions<'a>(
            parser: &mut Parser<'a>,
        ) -> Result<Option<Extensions<'a>>, ASNErrorVariant> {
            // TODO: check minimum version
            if let Some(tag) = parser.get_optional_explicit_tag(3)? {
                Ok(Some(Extensions::new(tag.contents)))
            } else {
                Ok(None)
            }
        }

        fn parse_tbs_cert<'a>(
            parser: &mut Parser<'a>,
        ) -> Result<TBSCertificate<'a>, ASNErrorVariant> {
            Ok(TBSCertificate::new(
                parse_version(parser)?,
                parser.expect::<Integer>()?,
                AlgorithmIdentifier::parse(parser.expect::<Sequence>()?)?,
                Name::new(parser.expect::<Sequence>()?),
                Validity::parse(parser.expect::<Sequence>()?)?,
                Name::new(parser.expect::<Sequence>()?),
                SubjectPublicKeyInfo::parse(parser.expect::<Sequence>()?)?,
                parse_optional_bitstring(parser, 1)?,
                parse_optional_bitstring(parser, 2)?,
                parse_extensions(parser)?,
            ))
        }

        Ok(Constructed::new(
            input,
            Parser::parse_all(input, parse_tbs_cert)?,
        ))
    }
}
