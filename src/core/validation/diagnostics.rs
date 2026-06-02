use std::path::Path;

use serde::Serialize;

use crate::{
    config::AppConfig,
    core::{
        cache::TokenCertificateCache,
        identity::{SigningIdentity, build_signing_identities},
        pkcs11::provider,
    },
};

#[derive(Debug, Serialize)]
pub struct DiagnosticsReport {
    pub app_version: String,
    pub server_host: String,
    pub server_port: u16,
    pub server_https: bool,
    pub configured_pkcs11_library_path: Option<String>,
    pub detected_pkcs11_library_path: Option<String>,
    pub driver_found: bool,
    pub driver_source: Option<String>,
    pub pcsc_available: bool,
    pub token_count: usize,
    pub certificate_count: usize,
    pub default_identity_id: Option<String>,
    pub identities: Vec<SigningIdentity>,
    pub expired_certificate_count: usize,
    pub expiring_soon_certificate_count: usize,
    pub tokens: Vec<DiagnosticToken>,
    pub certificates: Vec<DiagnosticCertificate>,
    pub last_error: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct DiagnosticToken {
    pub slot_id: u64,
    pub token_present: bool,
    pub label: Option<String>,
    pub manufacturer: Option<String>,
    pub model: Option<String>,
    pub serial_number: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct DiagnosticCertificate {
    pub slot_id: u64,
    pub id: Option<String>,
    pub label: Option<String>,
    pub subject: Option<String>,
    pub issuer: Option<String>,
    pub serial_number: Option<String>,
    pub not_after: Option<String>,
}

pub fn run_diagnostics(
    config: &AppConfig,
    cache: &TokenCertificateCache,
    app_version: impl Into<String>,
) -> DiagnosticsReport {
    let mut last_error = None;
    let library = match provider::detect_pkcs11_library(config) {
        Ok(library) => library,
        Err(error) => {
            last_error = Some(error.to_string());
            crate::models::pkcs11::Pkcs11LibraryInfo {
                found: false,
                path: None,
                source: None,
            }
        }
    };

    let snapshot = cache.snapshot().ok();
    let tokens = snapshot
        .as_ref()
        .map(|snapshot| snapshot.tokens.clone())
        .unwrap_or_default();
    let certificates = snapshot
        .as_ref()
        .map(|snapshot| snapshot.certificates.clone())
        .unwrap_or_default();
    let identities = build_signing_identities(&tokens, &certificates, config);
    let expired_certificate_count = identities
        .iter()
        .filter(|identity| identity.is_expired)
        .count();
    let expiring_soon_certificate_count = identities
        .iter()
        .filter(|identity| identity.expires_soon)
        .count();

    DiagnosticsReport {
        app_version: app_version.into(),
        server_host: config.server.host.clone(),
        server_port: config.server.port,
        server_https: config.server.https,
        configured_pkcs11_library_path: config.pkcs11.library_path.clone(),
        detected_pkcs11_library_path: library.path,
        driver_found: library.found,
        driver_source: library.source,
        pcsc_available: pcsc_available(),
        token_count: tokens.len(),
        certificate_count: certificates.len(),
        default_identity_id: (!config.signing.default_identity_id.trim().is_empty())
            .then(|| config.signing.default_identity_id.clone()),
        identities,
        expired_certificate_count,
        expiring_soon_certificate_count,
        tokens: tokens
            .into_iter()
            .map(|token| DiagnosticToken {
                slot_id: token.slot_id,
                token_present: token.token_present,
                label: token.label,
                manufacturer: token.manufacturer,
                model: token.model,
                serial_number: token.serial_number,
            })
            .collect(),
        certificates: certificates
            .into_iter()
            .map(|certificate| DiagnosticCertificate {
                slot_id: certificate.slot_id,
                id: certificate.id,
                label: certificate.label,
                subject: certificate.subject,
                issuer: certificate.issuer,
                serial_number: certificate.serial_number,
                not_after: certificate.not_after,
            })
            .collect(),
        last_error,
    }
}

fn pcsc_available() -> bool {
    [
        "/run/pcscd/pcscd.comm",
        "/var/run/pcscd/pcscd.comm",
        "/run/pcscd/pcscd.pub",
        "/var/run/pcscd/pcscd.pub",
    ]
    .iter()
    .any(|path| Path::new(path).exists())
}
