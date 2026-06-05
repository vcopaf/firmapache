use std::{env, time::Instant};

use thiserror::Error;
use tracing::{info, warn};

use crate::{
    config::AppConfig,
    core::{
        cache::{CacheError, TokenCertificateCache},
        identity::{self, IdentityError},
        signing::{
            compatible,
            session_manager::{self, SigningSessionError},
        },
    },
    models::{
        compatible::{CompatibleSignRequest, CompatibleSignResponse},
        signing::ApproveSigningSessionInput,
    },
};

pub enum DevelopmentAutoSign {
    Signed(CompatibleSignResponse),
    Fallback(String),
    NotEnabled,
}

pub fn try_auto_sign(
    config: &AppConfig,
    cache: &TokenCertificateCache,
    request: CompatibleSignRequest,
) -> Result<DevelopmentAutoSign, DevelopmentError> {
    let development = &config.development;
    if !development.enabled {
        return Ok(DevelopmentAutoSign::NotEnabled);
    }
    if !development.auto_sign {
        return Ok(DevelopmentAutoSign::NotEnabled);
    }

    let started = Instant::now();
    let result = try_auto_sign_inner(config, cache, request);
    match result {
        Ok(response) => {
            info!(
                signing_step = "development_auto_sign",
                elapsed_ms = started.elapsed().as_millis() as u64,
                "development auto-sign completed"
            );
            Ok(DevelopmentAutoSign::Signed(response))
        }
        Err(error) if development.fallback_to_modal => {
            warn!(
                error = %error,
                signing_step = "development_auto_sign",
                "development auto-sign failed; falling back to modal"
            );
            Ok(DevelopmentAutoSign::Fallback(error.to_string()))
        }
        Err(error) => Err(error),
    }
}

fn try_auto_sign_inner(
    config: &AppConfig,
    cache: &TokenCertificateCache,
    request: CompatibleSignRequest,
) -> Result<CompatibleSignResponse, DevelopmentError> {
    let identity_id = config.development.default_identity_id.trim();
    if identity_id.is_empty() {
        return Err(DevelopmentError::DefaultIdentityNotConfigured);
    }

    let prepared = compatible::prepare_sign_request(request)?;
    let identity = resolve_development_identity(cache, config, identity_id)?;
    let pin = development_pin(config, &identity)?;

    session_manager::sign_prepared_files(
        config,
        cache,
        &prepared.files,
        &prepared.format,
        ApproveSigningSessionInput {
            slot_id: identity.slot_id,
            certificate_id: identity.certificate_id,
            pin,
            identity_id: Some(identity.identity_id),
            provider: Some(identity.provider),
        },
    )
    .map_err(DevelopmentError::AutoSignFailed)
}

fn development_pin(
    config: &AppConfig,
    identity: &identity::ResolvedSigningIdentity,
) -> Result<String, DevelopmentError> {
    if config.development.remember_pin {
        if let Some(pin) = config
            .development
            .local_pin
            .as_deref()
            .filter(|pin| !pin.is_empty())
        {
            return Ok(pin.to_owned());
        }
    }

    let secret_env = if identity.provider == "pkcs12" {
        identity
            .password_env
            .as_deref()
            .ok_or(DevelopmentError::Pkcs12PasswordEnvironmentVariableNotFound)?
    } else {
        config.development.pin_env.trim()
    };
    env::var(secret_env)
        .ok()
        .filter(|pin| !pin.is_empty())
        .ok_or_else(|| {
            if identity.provider == "pkcs12" {
                DevelopmentError::Pkcs12PasswordEnvironmentVariableNotFound
            } else {
                DevelopmentError::PinEnvironmentVariableNotFound
            }
        })
}

fn resolve_development_identity(
    cache: &TokenCertificateCache,
    config: &AppConfig,
    identity_id: &str,
) -> Result<identity::ResolvedSigningIdentity, DevelopmentError> {
    match identity::resolve_signing_identity(cache, config, identity_id) {
        Ok(identity) => Ok(identity),
        Err(IdentityError::NotFound | IdentityError::NotAvailable | IdentityError::Cache(_)) => {
            let _ = cache.refresh_tokens_and_certificates(config);
            identity::resolve_signing_identity(cache, config, identity_id)
                .map_err(|_| DevelopmentError::IdentityNotAvailable)
        }
        Err(IdentityError::Expired) => Err(DevelopmentError::IdentityNotAvailable),
        Err(error) => Err(DevelopmentError::Identity(error)),
    }
}

#[derive(Debug, Error)]
pub enum DevelopmentError {
    #[error("Development mode is disabled")]
    Disabled,
    #[error("Development auto-sign is disabled")]
    AutoSignDisabled,
    #[error("Development default identity is not configured")]
    DefaultIdentityNotConfigured,
    #[error("Development identity is not available")]
    IdentityNotAvailable,
    #[error("Development PIN environment variable not found")]
    PinEnvironmentVariableNotFound,
    #[error("PKCS#12 password environment variable not found")]
    Pkcs12PasswordEnvironmentVariableNotFound,
    #[error("Development auto-sign failed: {0}")]
    AutoSignFailed(#[source] SigningSessionError),
    #[error(transparent)]
    Compatible(#[from] compatible::CompatibleSignError),
    #[error(transparent)]
    Identity(#[from] IdentityError),
    #[error(transparent)]
    Cache(#[from] CacheError),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        config::AppConfig,
        core::{
            cache::TokenCertificateCache,
            pkcs12::provider::{GenerateVirtualTokenInput, generate_virtual_token},
            validation::{jws as jws_validation, pdf as pdf_validation},
        },
        models::compatible::{CompatibleInputFile, CompatibleSignRequest},
    };
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    use lopdf::{Document, Object, Stream, dictionary};
    use std::{
        env, fs,
        io::Cursor,
        time::{SystemTime, UNIX_EPOCH},
    };

    #[test]
    fn development_auto_sign_uses_virtual_pkcs12_for_jws_and_pdf_without_modal() {
        let password = "clave-dev-autofirma";
        let path = temp_artifact_path("autofirma-token.p12");
        let generated = generate_virtual_token(GenerateVirtualTokenInput {
            id: "dev-token-autofirma".to_owned(),
            label: "Token virtual autofirma".to_owned(),
            common_name: "FirMapache Autofirma Test".to_owned(),
            organization: "FirMapache".to_owned(),
            country: "BO".to_owned(),
            validity_days: 30,
            password: password.to_owned(),
            output_path: path.clone(),
        })
        .expect("generate virtual token");
        let identity_id = generated.identity.identity_id.clone();
        let mut config = AppConfig::default();
        config.development.enabled = true;
        config.development.auto_sign = true;
        config.development.default_identity_id = identity_id;
        config.development.remember_pin = true;
        config.development.local_pin = Some(password.to_owned());
        config.development.pkcs12_tokens.push(generated.token);
        let cache = TokenCertificateCache::default();

        let jws = try_auto_sign(&config, &cache, jws_request()).expect("auto-sign JWS");
        let DevelopmentAutoSign::Signed(jws) = jws else {
            panic!("JWS auto-sign should complete without modal");
        };
        let jws_compact = STANDARD
            .decode(&jws.files[0].base64)
            .expect("JWS response Base64");
        let report = jws_validation::validate_jws_bytes(&jws_compact).expect("validate JWS");
        assert!(report.valid);

        let pdf = try_auto_sign(&config, &cache, pdf_request()).expect("auto-sign PDF");
        let DevelopmentAutoSign::Signed(pdf) = pdf else {
            panic!("PDF auto-sign should complete without modal");
        };
        let signed_pdf = STANDARD
            .decode(&pdf.files[0].base64)
            .expect("PDF response Base64");
        let report = pdf_validation::validate_pdf_bytes(&signed_pdf).expect("validate PDF");
        assert!(report.structurally_valid);
        assert!(report.contents_present);

        let _ = fs::remove_file(path);
    }

    fn jws_request() -> CompatibleSignRequest {
        CompatibleSignRequest {
            archivo: vec![CompatibleInputFile {
                base64: STANDARD.encode(br#"{"hola":"mundo"}"#),
                name: "solicitud.json".to_owned(),
            }],
            format: "jws".to_owned(),
            language: Some("es".to_owned()),
        }
    }

    fn pdf_request() -> CompatibleSignRequest {
        CompatibleSignRequest {
            archivo: vec![CompatibleInputFile {
                base64: STANDARD.encode(minimal_pdf()),
                name: "documento.pdf".to_owned(),
            }],
            format: "pdf".to_owned(),
            language: Some("es".to_owned()),
        }
    }

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

    fn temp_artifact_path(file_name: &str) -> String {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time")
            .as_nanos();
        let dir = env::temp_dir().join(format!("firmapache-autofirma-test-{nonce}"));
        fs::create_dir_all(&dir).expect("create temp test directory");
        dir.join(file_name).to_string_lossy().into_owned()
    }
}
