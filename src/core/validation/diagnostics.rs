use std::{env, path::Path};

use serde::Serialize;

use crate::{
    config::AppConfig,
    core::{
        cache::TokenCertificateCache,
        identity::{SigningIdentity, build_signing_identities},
        pkcs11::provider,
    },
    metadata,
};

#[derive(Debug, Serialize)]
pub struct DiagnosticsReport {
    pub app_name: String,
    pub app_version: String,
    pub build_date: String,
    pub git_commit: String,
    pub release_channel: String,
    pub server_host: String,
    pub server_port: u16,
    pub server_https: bool,
    pub server_url: String,
    pub server_active: bool,
    pub last_restart_error: Option<String>,
    pub development_enabled: bool,
    pub development_auto_sign: bool,
    pub development_default_identity_id: Option<String>,
    pub development_pin_env: String,
    pub development_pin_env_defined: bool,
    pub development_remember_pin: bool,
    pub development_has_local_pin: bool,
    pub signing_mode: String,
    pub signing_auto_sign_will_run: bool,
    pub signing_active_identity_id: Option<String>,
    pub signing_active_identity_name: Option<String>,
    pub signing_active_provider: Option<String>,
    pub signing_pin_remembered: bool,
    pub signing_state_issues: Vec<String>,
    pub configured_pkcs11_library_path: Option<String>,
    pub detected_pkcs11_library_path: Option<String>,
    pub driver_found: bool,
    pub driver_source: Option<String>,
    pub pcsc_available: bool,
    pub watcher_active: bool,
    pub watcher_backend: Option<String>,
    pub watcher_last_event: Option<String>,
    pub watcher_last_event_at: Option<String>,
    pub token_cache_loaded_at: Option<String>,
    pub certificate_cache_loaded_at: Option<String>,
    pub cache_hits: u64,
    pub cache_misses: u64,
    pub token_count: usize,
    pub certificate_count: usize,
    pub default_identity_id: Option<String>,
    pub identities: Vec<SigningIdentity>,
    pub expired_certificate_count: usize,
    pub expiring_soon_certificate_count: usize,
    pub tokens: Vec<DiagnosticToken>,
    pub certificates: Vec<DiagnosticCertificate>,
    pub pkcs12_tokens: Vec<DiagnosticPkcs12Token>,
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

#[derive(Debug, Serialize)]
pub struct DiagnosticPkcs12Token {
    pub id: String,
    pub label: String,
    pub path: String,
    pub path_exists: bool,
    pub password_env: String,
    pub password_env_defined: bool,
    pub remember_password: bool,
    pub has_local_password: bool,
    pub certificate_readable: bool,
    pub subject: Option<String>,
    pub issuer: Option<String>,
    pub not_after: Option<String>,
}

pub fn run_diagnostics(config: &AppConfig, cache: &TokenCertificateCache) -> DiagnosticsReport {
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
    let signing_state = diagnostic_signing_state(config, &identities);
    let expired_certificate_count = identities
        .iter()
        .filter(|identity| identity.is_expired)
        .count();
    let expiring_soon_certificate_count = identities
        .iter()
        .filter(|identity| identity.expires_soon)
        .count();

    DiagnosticsReport {
        app_name: metadata::APP_NAME.to_owned(),
        app_version: metadata::APP_VERSION.to_owned(),
        build_date: metadata::BUILD_DATE.to_owned(),
        git_commit: metadata::GIT_COMMIT.to_owned(),
        release_channel: metadata::RELEASE_CHANNEL.to_owned(),
        server_host: config.server.host.clone(),
        server_port: config.server.port,
        server_https: config.server.https,
        server_url: server_url(config),
        server_active: true,
        last_restart_error: None,
        development_enabled: config.development.enabled,
        development_auto_sign: config.development.auto_sign,
        development_default_identity_id: (!config
            .development
            .default_identity_id
            .trim()
            .is_empty())
        .then(|| config.development.default_identity_id.clone()),
        development_pin_env: config.development.pin_env.clone(),
        development_pin_env_defined: env::var(&config.development.pin_env).is_ok(),
        development_remember_pin: config.development.remember_pin,
        development_has_local_pin: config
            .development
            .local_pin
            .as_deref()
            .is_some_and(|pin| !pin.is_empty()),
        signing_mode: signing_state.mode_label,
        signing_auto_sign_will_run: signing_state.auto_sign_will_run,
        signing_active_identity_id: signing_state.active_identity_id,
        signing_active_identity_name: signing_state.active_identity_name,
        signing_active_provider: signing_state.active_provider,
        signing_pin_remembered: signing_state.pin_remembered,
        signing_state_issues: signing_state.issues,
        configured_pkcs11_library_path: config.pkcs11.library_path.clone(),
        detected_pkcs11_library_path: library.path,
        driver_found: library.found,
        driver_source: library.source,
        pcsc_available: pcsc_available(),
        watcher_active: snapshot
            .as_ref()
            .is_some_and(|snapshot| snapshot.watcher_active),
        watcher_backend: snapshot
            .as_ref()
            .and_then(|snapshot| snapshot.watcher_backend.clone()),
        watcher_last_event: snapshot
            .as_ref()
            .and_then(|snapshot| snapshot.last_event.clone()),
        watcher_last_event_at: snapshot
            .as_ref()
            .and_then(|snapshot| snapshot.last_event_at.map(|event_at| event_at.to_rfc3339())),
        token_cache_loaded_at: snapshot
            .as_ref()
            .and_then(|snapshot| snapshot.loaded_at.map(|loaded_at| loaded_at.to_rfc3339())),
        certificate_cache_loaded_at: snapshot.as_ref().and_then(|snapshot| {
            snapshot
                .certificates_loaded_at
                .map(|loaded_at| loaded_at.to_rfc3339())
        }),
        cache_hits: snapshot
            .as_ref()
            .map(|snapshot| snapshot.cache_hits)
            .unwrap_or_default(),
        cache_misses: snapshot
            .as_ref()
            .map(|snapshot| snapshot.cache_misses)
            .unwrap_or_default(),
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
        pkcs12_tokens: config
            .development
            .pkcs12_tokens
            .iter()
            .map(|token| {
                let identity = crate::core::pkcs12::provider::test_token(token).ok();
                DiagnosticPkcs12Token {
                    id: token.id.clone(),
                    label: token.label.clone(),
                    path: token.path.clone(),
                    path_exists: Path::new(&token.path).exists(),
                    password_env: token.password_env.clone(),
                    password_env_defined: !token.password_env.is_empty()
                        && env::var(&token.password_env).is_ok(),
                    remember_password: token.remember_password,
                    has_local_password: token
                        .local_password
                        .as_deref()
                        .is_some_and(|password| !password.is_empty()),
                    certificate_readable: identity.is_some(),
                    subject: identity
                        .as_ref()
                        .and_then(|identity| identity.subject.clone()),
                    issuer: identity
                        .as_ref()
                        .and_then(|identity| identity.issuer.clone()),
                    not_after: identity
                        .as_ref()
                        .and_then(|identity| identity.not_after.clone()),
                }
            })
            .collect(),
        last_error,
    }
}

struct DiagnosticSigningState {
    mode_label: String,
    auto_sign_will_run: bool,
    active_identity_id: Option<String>,
    active_identity_name: Option<String>,
    active_provider: Option<String>,
    pin_remembered: bool,
    issues: Vec<String>,
}

fn diagnostic_signing_state(
    config: &AppConfig,
    identities: &[SigningIdentity],
) -> DiagnosticSigningState {
    let dev_enabled = config.development.enabled;
    let auto_sign = config.development.auto_sign;
    let active_identity = (!config.development.default_identity_id.trim().is_empty())
        .then(|| {
            identities
                .iter()
                .find(|identity| identity.identity_id == config.development.default_identity_id)
        })
        .flatten();
    let pin_remembered = config
        .development
        .local_pin
        .as_deref()
        .is_some_and(|pin| !pin.is_empty());
    let pin_available = pin_remembered || env::var(&config.development.pin_env).is_ok();
    let mut issues = Vec::new();

    if dev_enabled && auto_sign {
        if config.development.default_identity_id.trim().is_empty() {
            issues.push("identidad no configurada".to_owned());
        } else if let Some(identity) = active_identity {
            if !identity.is_available {
                issues.push("identidad no disponible".to_owned());
            }
            if identity.is_expired {
                issues.push("certificado expirado".to_owned());
            }
        } else {
            issues.push("identidad inexistente".to_owned());
        }
        if !pin_available {
            issues.push("PIN no disponible".to_owned());
        }
    }

    let mode_label = if dev_enabled && auto_sign && issues.is_empty() {
        "Autofirma".to_owned()
    } else if dev_enabled && auto_sign && !issues.is_empty() {
        "Confirmación manual (autofirma incompleta)".to_owned()
    } else {
        "Confirmación manual".to_owned()
    };

    DiagnosticSigningState {
        mode_label,
        auto_sign_will_run: dev_enabled && auto_sign && issues.is_empty(),
        active_identity_id: active_identity.map(|identity| identity.identity_id.clone()),
        active_identity_name: active_identity.map(identity_display_name),
        active_provider: active_identity.map(|identity| {
            if identity.provider == "pkcs12" {
                "PKCS#12".to_owned()
            } else {
                "PKCS#11".to_owned()
            }
        }),
        pin_remembered,
        issues,
    }
}

fn identity_display_name(identity: &SigningIdentity) -> String {
    let title = identity
        .subject
        .as_deref()
        .or(identity.certificate_label.as_deref())
        .or(identity.certificate_id.as_deref())
        .unwrap_or(&identity.identity_id);
    title.to_owned()
}

fn server_url(config: &AppConfig) -> String {
    let scheme = if config.server.https { "https" } else { "http" };
    let host = if config.server.host == "127.0.0.1" {
        "localhost"
    } else {
        config.server.host.as_str()
    };
    format!("{scheme}://{host}:{}/", config.server.port)
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
