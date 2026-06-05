use std::{fs, io::Cursor, path::Path, time::Instant};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use chrono::{Local, Utc};
use lopdf::{Dictionary, Document, Object, ObjectId, StringFormat, dictionary};
use sha2::{Digest, Sha256};
use tracing::info;

use crate::{
    config::AppConfig,
    core::{
        cache::TokenCertificateCache,
        pkcs11::provider,
        pkcs12,
        signing::jws::{self, JwsSignError},
    },
    models::signing::ApproveSigningSessionInput,
};

use super::{cms, document::inspect_pdf_bytes, error::PdfError};

const CONTENTS_RESERVED_BYTES: usize = 32 * 1024;
const BYTE_RANGE_SENTINEL: i64 = 9_999_999_999;

#[derive(Debug)]
struct SignatureOffsets {
    contents_start: usize,
    contents_end: usize,
}

pub fn sign_pdf_file(
    config: &AppConfig,
    cache: &TokenCertificateCache,
    path: impl AsRef<Path>,
    input: ApproveSigningSessionInput,
) -> Result<Vec<u8>, PdfError> {
    let path = path.as_ref();
    if path.as_os_str().is_empty() {
        return Err(PdfError::EmptyPath);
    }
    let metadata = fs::metadata(path)?;
    if !metadata.is_file() {
        return Err(PdfError::NotAFile);
    }

    let source = fs::read(path)?;
    sign_pdf_bytes(config, cache, &source, file_name(path), input)
}

pub fn sign_pdf_bytes(
    config: &AppConfig,
    cache: &TokenCertificateCache,
    pdf_bytes: &[u8],
    file_name: String,
    input: ApproveSigningSessionInput,
) -> Result<Vec<u8>, PdfError> {
    let started = Instant::now();
    validate_input(&input)?;
    let info = inspect_pdf_bytes(file_name, pdf_bytes.len() as u64, pdf_bytes);
    if !info.valid_header {
        return Err(PdfError::InvalidPdf);
    }
    if !info.has_eof_marker {
        return Err(PdfError::InvalidPdf);
    }

    let certificate_der_base64 = jws::certificate_der_base64_for_input(config, cache, &input)?;
    let certificate_der = STANDARD
        .decode(certificate_der_base64.as_bytes())
        .map_err(|_| PdfError::InvalidCertificateBase64)?;

    let mut prepared = prepare_pdf_for_signature(pdf_bytes)?;
    let offsets = patch_byte_range(&mut prepared)?;
    let content_digest = digest_byte_range(&prepared, &offsets);
    let signed_attrs = cms::signed_attrs_der(&content_digest, &certificate_der)?;
    let signature = if input.provider.as_deref() == Some("pkcs12") {
        let identity_id = input
            .identity_id
            .as_deref()
            .ok_or(JwsSignError::MissingCertificateSelection)?;
        pkcs12::provider::sign_rs256(config, identity_id, &input.pin, &signed_attrs)?
    } else {
        provider::sign_rs256(
            config,
            input.slot_id,
            input.certificate_id,
            input.pin,
            &signed_attrs,
        )?
    };
    let cms = cms::build_detached_cades(&certificate_der, &signed_attrs, &signature)?;
    insert_cms_signature(&mut prepared, &offsets, &cms)?;

    info!(
        signing_step = "sign_pdf",
        elapsed_ms = started.elapsed().as_millis() as u64,
        pdf_size = prepared.len(),
        cms_size = cms.len(),
        "PDF signed with detached CAdES signature"
    );

    Ok(prepared)
}

fn prepare_pdf_for_signature(source: &[u8]) -> Result<Vec<u8>, PdfError> {
    let mut document = Document::load_mem(source)?;
    let pages = document.get_pages();
    let first_page_id = pages.values().next().copied().ok_or(PdfError::InvalidPdf)?;

    let signature_id = document.add_object(signature_dictionary());
    let widget_id = document.add_object(signature_widget(signature_id, first_page_id));
    append_widget_to_page(&mut document, first_page_id, widget_id)?;
    append_widget_to_acroform(&mut document, widget_id)?;

    let mut prepared = Vec::new();
    document
        .save_to(&mut Cursor::new(&mut prepared))
        .map_err(PdfError::Write)?;
    Ok(prepared)
}

fn patch_byte_range(prepared: &mut [u8]) -> Result<SignatureOffsets, PdfError> {
    let contents_placeholder = contents_placeholder();
    let contents_start = find_bytes(prepared, &contents_placeholder)
        .ok_or(PdfError::PlaceholderNotFound("Contents"))?;
    let contents_end = contents_start + contents_placeholder.len();
    let byte_range = [
        0usize,
        contents_start,
        contents_end,
        prepared.len().saturating_sub(contents_end),
    ];

    let placeholder = byte_range_placeholder();
    let byte_range_start = find_bytes(prepared, placeholder.as_bytes())
        .ok_or(PdfError::PlaceholderNotFound("ByteRange"))?;
    let replacement = format!("[0 {} {} {}]", byte_range[1], byte_range[2], byte_range[3]);
    if replacement.len() > placeholder.len() {
        return Err(PdfError::PlaceholderNotFound("ByteRange too small"));
    }

    let mut padded = replacement.into_bytes();
    padded.resize(placeholder.len(), b' ');
    prepared[byte_range_start..byte_range_start + placeholder.len()].copy_from_slice(&padded);

    Ok(SignatureOffsets {
        contents_start,
        contents_end,
    })
}

fn insert_cms_signature(
    prepared: &mut [u8],
    offsets: &SignatureOffsets,
    cms: &[u8],
) -> Result<(), PdfError> {
    if cms.len() > CONTENTS_RESERVED_BYTES {
        return Err(PdfError::CmsTooLarge {
            actual: cms.len(),
            reserved: CONTENTS_RESERVED_BYTES,
        });
    }

    let hex = hex_upper(cms);
    let hex_start = offsets.contents_start + 1;
    let hex_end = offsets.contents_end - 1;
    prepared[hex_start..hex_end].fill(b'0');
    prepared[hex_start..hex_start + hex.len()].copy_from_slice(hex.as_bytes());
    Ok(())
}

fn signature_dictionary() -> Dictionary {
    dictionary! {
        "Type" => Object::Name(b"Sig".to_vec()),
        "Filter" => Object::Name(b"Adobe.PPKLite".to_vec()),
        "SubFilter" => Object::Name(b"ETSI.CAdES.detached".to_vec()),
        "M" => Object::string_literal(pdf_date_now()),
        "Name" => Object::string_literal(""),
        "Reason" => Object::string_literal(""),
        "Location" => Object::string_literal(""),
        "ContactInfo" => Object::string_literal(""),
        "ByteRange" => Object::Array(vec![
            Object::Integer(0),
            Object::Integer(BYTE_RANGE_SENTINEL),
            Object::Integer(BYTE_RANGE_SENTINEL),
            Object::Integer(BYTE_RANGE_SENTINEL),
        ]),
        "Contents" => Object::String(vec![0; CONTENTS_RESERVED_BYTES], StringFormat::Hexadecimal),
    }
}

fn pdf_date_now() -> String {
    let now = Local::now();
    let offset = now.format("%z").to_string();
    if offset.len() == 5 {
        let sign = &offset[..1];
        let hours = &offset[1..3];
        let minutes = &offset[3..5];
        return format!(
            "D:{}{}{}'{}'",
            now.format("%Y%m%d%H%M%S"),
            sign,
            hours,
            minutes
        );
    }

    format!("D:{}Z", Utc::now().format("%Y%m%d%H%M%S"))
}

fn signature_widget(signature_id: ObjectId, page_id: ObjectId) -> Dictionary {
    dictionary! {
        "Type" => Object::Name(b"Annot".to_vec()),
        "Subtype" => Object::Name(b"Widget".to_vec()),
        "FT" => Object::Name(b"Sig".to_vec()),
        "T" => Object::string_literal("FirMapache"),
        "F" => Object::Integer(132),
        "Rect" => Object::Array(vec![
            Object::Real(0.0),
            Object::Real(0.0),
            Object::Real(0.0),
            Object::Real(0.0),
        ]),
        "V" => Object::Reference(signature_id),
        "P" => Object::Reference(page_id),
    }
}

fn append_widget_to_page(
    document: &mut Document,
    page_id: ObjectId,
    widget_id: ObjectId,
) -> Result<(), PdfError> {
    let page = document.get_object_mut(page_id)?.as_dict_mut()?;
    match page.get_mut(b"Annots") {
        Ok(Object::Array(annots)) => annots.push(Object::Reference(widget_id)),
        Ok(Object::Reference(annots_id)) => {
            let annots_id = *annots_id;
            let annots = document.get_object_mut(annots_id)?.as_array_mut()?;
            annots.push(Object::Reference(widget_id));
        }
        _ => {
            page.set("Annots", Object::Array(vec![Object::Reference(widget_id)]));
        }
    }
    Ok(())
}

fn append_widget_to_acroform(document: &mut Document, widget_id: ObjectId) -> Result<(), PdfError> {
    let acroform = document.catalog()?.get(b"AcroForm").ok().cloned();
    match acroform {
        Some(Object::Reference(acroform_id)) => {
            let acroform = document.get_object_mut(acroform_id)?.as_dict_mut()?;
            append_field_to_acroform_dict(acroform, widget_id)?;
        }
        Some(Object::Dictionary(mut acroform)) => {
            append_field_to_acroform_dict(&mut acroform, widget_id)?;
            document
                .catalog_mut()?
                .set("AcroForm", Object::Dictionary(acroform));
        }
        _ => {
            let acroform_id = document.add_object(dictionary! {
                "Fields" => Object::Array(vec![Object::Reference(widget_id)]),
                "SigFlags" => Object::Integer(3),
            });
            document
                .catalog_mut()?
                .set("AcroForm", Object::Reference(acroform_id));
        }
    }
    Ok(())
}

fn append_field_to_acroform_dict(
    acroform: &mut Dictionary,
    widget_id: ObjectId,
) -> Result<(), PdfError> {
    match acroform.get_mut(b"Fields") {
        Ok(Object::Array(fields)) => fields.push(Object::Reference(widget_id)),
        _ => acroform.set("Fields", Object::Array(vec![Object::Reference(widget_id)])),
    }
    acroform.set("SigFlags", Object::Integer(3));
    Ok(())
}

fn digest_byte_range(prepared: &[u8], offsets: &SignatureOffsets) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(&prepared[..offsets.contents_start]);
    hasher.update(&prepared[offsets.contents_end..]);
    hasher.finalize().to_vec()
}

fn validate_input(input: &ApproveSigningSessionInput) -> Result<(), PdfError> {
    if input.certificate_id.trim().is_empty() {
        return Err(PdfError::Jws(JwsSignError::MissingCertificateSelection));
    }
    if input.pin.is_empty() {
        return Err(PdfError::Jws(JwsSignError::MissingPin));
    }
    Ok(())
}

fn contents_placeholder() -> Vec<u8> {
    let mut placeholder = Vec::with_capacity(2 + CONTENTS_RESERVED_BYTES * 2);
    placeholder.push(b'<');
    placeholder.extend(std::iter::repeat_n(b'0', CONTENTS_RESERVED_BYTES * 2));
    placeholder.push(b'>');
    placeholder
}

fn byte_range_placeholder() -> String {
    format!("[0 {BYTE_RANGE_SENTINEL} {BYTE_RANGE_SENTINEL} {BYTE_RANGE_SENTINEL}]")
}

fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

fn hex_upper(bytes: &[u8]) -> String {
    let mut hex = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(hex, "{byte:02X}");
    }
    hex
}

fn file_name(path: &Path) -> String {
    path.file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("documento.pdf")
        .to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use lopdf::{Object, Stream};

    fn minimal_pdf() -> Vec<u8> {
        let mut document = Document::with_version("1.7");
        let pages_id = document.new_object_id();
        let page_id = document.new_object_id();
        let content_id = document.add_object(Stream::new(dictionary! {}, b"BT ET".to_vec()));
        document.objects.insert(
            pages_id,
            dictionary! {
                "Type" => Object::Name(b"Pages".to_vec()),
                "Kids" => Object::Array(vec![Object::Reference(page_id)]),
                "Count" => Object::Integer(1),
            }
            .into(),
        );
        document.objects.insert(
            page_id,
            dictionary! {
                "Type" => Object::Name(b"Page".to_vec()),
                "Parent" => Object::Reference(pages_id),
                "MediaBox" => Object::Array(vec![
                    Object::Integer(0),
                    Object::Integer(0),
                    Object::Integer(200),
                    Object::Integer(200),
                ]),
                "Contents" => Object::Reference(content_id),
            }
            .into(),
        );
        let catalog_id = document.add_object(dictionary! {
            "Type" => Object::Name(b"Catalog".to_vec()),
            "Pages" => Object::Reference(pages_id),
        });
        document.trailer.set("Root", Object::Reference(catalog_id));
        let mut bytes = Vec::new();
        document
            .save_to(&mut Cursor::new(&mut bytes))
            .expect("save PDF");
        bytes
    }

    #[test]
    fn prepares_pdf_signature_dictionary_and_byte_range() {
        let source = minimal_pdf();
        let mut prepared = prepare_pdf_for_signature(&source).expect("prepare PDF");
        let offsets = patch_byte_range(&mut prepared).expect("patch ByteRange");
        insert_cms_signature(&mut prepared, &offsets, b"fake-cms").expect("insert CMS");
        let text = String::from_utf8_lossy(&prepared);

        assert!(text.contains("/Adobe.PPKLite"));
        assert!(text.contains("/ETSI.CAdES.detached"));
        assert!(text.contains("/M (D:") || text.contains("/M(D:"));
        assert!(text.contains("/Name ()") || text.contains("/Name()"));
        assert!(text.contains("/Reason ()") || text.contains("/Reason()"));
        assert!(text.contains("/Location ()") || text.contains("/Location()"));
        assert!(text.contains("/ContactInfo ()") || text.contains("/ContactInfo()"));
        assert!(text.contains("/ByteRange"));
        assert!(!text.contains(&BYTE_RANGE_SENTINEL.to_string()));
        assert!(
            text.contains("/Contents <66616B652D636D73")
                || text.contains("/Contents<66616B652D636D73")
        );
    }
}
