use sha2::{Digest, Sha256};
use time::OffsetDateTime;
use x509_parser::parse_x509_certificate;
use yasna::models::{ObjectIdentifier, UTCTime};

use super::error::PdfError;

const OID_DATA: &[u64] = &[1, 2, 840, 113549, 1, 7, 1];
const OID_SIGNED_DATA: &[u64] = &[1, 2, 840, 113549, 1, 7, 2];
const OID_CONTENT_TYPE: &[u64] = &[1, 2, 840, 113549, 1, 9, 3];
const OID_MESSAGE_DIGEST: &[u64] = &[1, 2, 840, 113549, 1, 9, 4];
const OID_SIGNING_TIME: &[u64] = &[1, 2, 840, 113549, 1, 9, 5];
const OID_SIGNING_CERTIFICATE_V2: &[u64] = &[1, 2, 840, 113549, 1, 9, 16, 2, 47];
const OID_SHA256: &[u64] = &[2, 16, 840, 1, 101, 3, 4, 2, 1];
const OID_RSA_ENCRYPTION: &[u64] = &[1, 2, 840, 113549, 1, 1, 1];

pub fn signed_attrs_der(
    content_digest: &[u8],
    certificate_der: &[u8],
) -> Result<Vec<u8>, PdfError> {
    let cert_hash = Sha256::digest(certificate_der);
    let signing_time = OffsetDateTime::now_utc()
        .replace_nanosecond(0)
        .map_err(|_| PdfError::InvalidCertificate)?;
    let signing_time =
        UTCTime::from_datetime_opt(signing_time).ok_or(PdfError::InvalidCertificate)?;

    let mut attrs = vec![
        content_type_attr(),
        message_digest_attr(content_digest),
        signing_time_attr(&signing_time),
        signing_certificate_v2_attr(&cert_hash),
    ];
    attrs.sort();

    let content = attrs.into_iter().flatten().collect::<Vec<_>>();
    Ok(der_wrap(0x31, &content))
}

pub fn build_detached_cades(
    certificate_der: &[u8],
    signed_attrs_der: &[u8],
    signature: &[u8],
) -> Result<Vec<u8>, PdfError> {
    let (_, certificate) =
        parse_x509_certificate(certificate_der).map_err(|_| PdfError::InvalidCertificate)?;
    let issuer_der = certificate.tbs_certificate.issuer.as_raw();
    let serial_der = positive_integer_der(certificate.tbs_certificate.raw_serial());

    let signed_attrs_tagged = der_wrap(0xa0, der_content(signed_attrs_der)?);
    let signer_info = yasna::construct_der(|writer| {
        writer.write_sequence(|writer| {
            writer.next().write_u8(1);
            writer.next().write_sequence(|writer| {
                writer.next().write_der(issuer_der);
                writer.next().write_der(&serial_der);
            });
            writer.next().write_der(&algorithm_identifier_sha256());
            writer.next().write_der(&signed_attrs_tagged);
            writer.next().write_der(&algorithm_identifier_rsa());
            writer.next().write_bytes(signature);
        });
    });

    let signed_data = yasna::construct_der(|writer| {
        writer.write_sequence(|writer| {
            writer.next().write_u8(1);
            writer.next().write_set(|writer| {
                writer.next().write_der(&algorithm_identifier_sha256());
            });
            writer.next().write_sequence(|writer| {
                writer.next().write_oid(&oid(OID_DATA));
            });
            writer.next().write_der(&der_wrap(0xa0, certificate_der));
            writer.next().write_set(|writer| {
                writer.next().write_der(&signer_info);
            });
        });
    });

    Ok(yasna::construct_der(|writer| {
        writer.write_sequence(|writer| {
            writer.next().write_oid(&oid(OID_SIGNED_DATA));
            writer.next().write_der(&der_wrap(0xa0, &signed_data));
        });
    }))
}

fn content_type_attr() -> Vec<u8> {
    attribute(OID_CONTENT_TYPE, |writer| {
        writer.next().write_oid(&oid(OID_DATA));
    })
}

fn message_digest_attr(content_digest: &[u8]) -> Vec<u8> {
    attribute(OID_MESSAGE_DIGEST, |writer| {
        writer.next().write_bytes(content_digest);
    })
}

fn signing_time_attr(signing_time: &UTCTime) -> Vec<u8> {
    attribute(OID_SIGNING_TIME, |writer| {
        writer.next().write_utctime(signing_time);
    })
}

fn signing_certificate_v2_attr(cert_hash: &[u8]) -> Vec<u8> {
    attribute(OID_SIGNING_CERTIFICATE_V2, |writer| {
        writer.next().write_sequence(|writer| {
            writer.next().write_sequence(|writer| {
                writer.next().write_sequence(|writer| {
                    writer.next().write_bytes(cert_hash);
                });
            });
        });
    })
}

fn attribute<F>(attribute_oid: &[u64], values: F) -> Vec<u8>
where
    F: FnOnce(&mut yasna::DERWriterSet),
{
    yasna::construct_der(|writer| {
        writer.write_sequence(|writer| {
            writer.next().write_oid(&oid(attribute_oid));
            writer.next().write_set(values);
        });
    })
}

fn algorithm_identifier_sha256() -> Vec<u8> {
    yasna::construct_der(|writer| {
        writer.write_sequence(|writer| {
            writer.next().write_oid(&oid(OID_SHA256));
        });
    })
}

fn algorithm_identifier_rsa() -> Vec<u8> {
    yasna::construct_der(|writer| {
        writer.write_sequence(|writer| {
            writer.next().write_oid(&oid(OID_RSA_ENCRYPTION));
            writer.next().write_null();
        });
    })
}

fn oid(parts: &[u64]) -> ObjectIdentifier {
    ObjectIdentifier::from_slice(parts)
}

pub(crate) fn der_wrap(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut der = Vec::with_capacity(1 + 5 + content.len());
    der.push(tag);
    der.extend(der_len(content.len()));
    der.extend(content);
    der
}

fn der_len(len: usize) -> Vec<u8> {
    if len < 128 {
        return vec![len as u8];
    }

    let bytes = len.to_be_bytes();
    let first = bytes
        .iter()
        .position(|byte| *byte != 0)
        .unwrap_or(bytes.len() - 1);
    let len_bytes = &bytes[first..];
    let mut encoded = Vec::with_capacity(1 + len_bytes.len());
    encoded.push(0x80 | len_bytes.len() as u8);
    encoded.extend(len_bytes);
    encoded
}

fn der_content(der: &[u8]) -> Result<&[u8], PdfError> {
    if der.len() < 2 {
        return Err(PdfError::InvalidCertificate);
    }
    let first_len = der[1];
    if first_len & 0x80 == 0 {
        let start = 2;
        let end = start + first_len as usize;
        return der.get(start..end).ok_or(PdfError::InvalidCertificate);
    }
    let len_len = (first_len & 0x7f) as usize;
    if len_len == 0 || der.len() < 2 + len_len {
        return Err(PdfError::InvalidCertificate);
    }
    let mut len = 0usize;
    for byte in &der[2..2 + len_len] {
        len = (len << 8) | *byte as usize;
    }
    let start = 2 + len_len;
    let end = start + len;
    der.get(start..end).ok_or(PdfError::InvalidCertificate)
}

fn positive_integer_der(raw_serial: &[u8]) -> Vec<u8> {
    let mut serial = raw_serial.to_vec();
    while serial.len() > 1 && serial[0] == 0 && serial[1] & 0x80 == 0 {
        serial.remove(0);
    }
    if serial.first().is_some_and(|byte| byte & 0x80 != 0) {
        serial.insert(0, 0);
    }
    der_wrap(0x02, &serial)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wraps_der_long_lengths() {
        let der = der_wrap(0x04, &[0u8; 300]);
        assert_eq!(der[0], 0x04);
        assert_eq!(&der[1..4], &[0x82, 0x01, 0x2c]);
        assert_eq!(der.len(), 304);
    }

    #[test]
    fn encodes_positive_integer_with_padding_when_needed() {
        assert_eq!(
            positive_integer_der(&[0x80, 0x01]),
            vec![0x02, 0x03, 0x00, 0x80, 0x01]
        );
    }
}
