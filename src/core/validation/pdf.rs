use serde::Serialize;
use thiserror::Error;

#[derive(Debug, Serialize)]
pub struct PdfValidationReport {
    pub signature_detected: bool,
    pub byte_range_present: bool,
    pub contents_present: bool,
    pub filter_adobe_ppklite: bool,
    pub subfilter_cades_detached: bool,
    pub m_present: bool,
    pub name_present: bool,
    pub reason_present: bool,
    pub location_present: bool,
    pub contact_info_present: bool,
    pub structurally_valid: bool,
    pub internal_signature_verification: Option<bool>,
    pub recommendation: Option<String>,
}

#[derive(Debug, Error)]
pub enum PdfValidationError {
    #[error("PDF file is empty")]
    Empty,
    #[error("input does not look like a PDF")]
    InvalidPdf,
}

pub fn validate_pdf_bytes(input: &[u8]) -> Result<PdfValidationReport, PdfValidationError> {
    if input.is_empty() {
        return Err(PdfValidationError::Empty);
    }
    if !input.starts_with(b"%PDF-") {
        return Err(PdfValidationError::InvalidPdf);
    }

    let signature_detected = contains(input, b"/Type/Sig") || contains(input, b"/Type /Sig");
    let byte_range_present = contains(input, b"/ByteRange");
    let contents_present = contains(input, b"/Contents");
    let filter_adobe_ppklite =
        contains(input, b"/Filter/Adobe.PPKLite") || contains(input, b"/Filter /Adobe.PPKLite");
    let subfilter_cades_detached = contains(input, b"/SubFilter/ETSI.CAdES.detached")
        || contains(input, b"/SubFilter /ETSI.CAdES.detached");
    let m_present = contains(input, b"/M(") || contains(input, b"/M (");
    let name_present = contains(input, b"/Name(") || contains(input, b"/Name (");
    let reason_present = contains(input, b"/Reason(") || contains(input, b"/Reason (");
    let location_present = contains(input, b"/Location(") || contains(input, b"/Location (");
    let contact_info_present =
        contains(input, b"/ContactInfo(") || contains(input, b"/ContactInfo (");
    let structurally_valid = signature_detected
        && byte_range_present
        && contents_present
        && filter_adobe_ppklite
        && subfilter_cades_detached
        && m_present;

    Ok(PdfValidationReport {
        signature_detected,
        byte_range_present,
        contents_present,
        filter_adobe_ppklite,
        subfilter_cades_detached,
        m_present,
        name_present,
        reason_present,
        location_present,
        contact_info_present,
        structurally_valid,
        internal_signature_verification: None,
        recommendation: Some(
            "Verificacion criptografica PDF interna aun no implementada; use `pdfsig archivo.pdf` para validacion completa."
                .to_owned(),
        ),
    })
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_signed_pdf_markers() {
        let pdf =
            b"%PDF-1.7\n<</Type/Sig/Filter/Adobe.PPKLite/SubFilter/ETSI.CAdES.detached/M(D:20260601120000-04'00')/Name()/Reason()/Location()/ContactInfo()/ByteRange[0 1 2 3]/Contents<00>>\n%%EOF";

        let report = validate_pdf_bytes(pdf).expect("PDF report");

        assert!(report.signature_detected);
        assert!(report.structurally_valid);
        assert!(report.contact_info_present);
    }
}
