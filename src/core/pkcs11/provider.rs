use std::{env, path::Path, sync::Mutex, time::Instant};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use cryptoki::{
    context::{CInitializeArgs, Pkcs11},
    mechanism::Mechanism,
    object::{Attribute, AttributeType, CertificateType, ObjectClass, ObjectHandle},
    session::{Session, UserType},
    types::AuthPin,
};
use sha2::{Digest, Sha256};
use thiserror::Error;
use tracing::{info, warn};
use x509_parser::{parse_x509_certificate, time::ASN1Time};

use crate::{
    config::AppConfig,
    models::pkcs11::{
        CertificateInfo, Pkcs11LibraryInfo, SignHashRequest, SignHashResponse, TokenInfo,
    },
};

const PKCS11_LIBRARY_ENV: &str = "FIRMAPACHE_PKCS11";
const LEGACY_PKCS11_LIBRARY_ENV: &str = "MINI_FIRMADOR_PKCS11";
const SHA256_DIGEST_INFO_PREFIX: [u8; 19] = [
    0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
    0x00, 0x04, 0x20,
];

const COMMON_PKCS11_LIBRARY_PATHS: [&str; 5] = [
    "/usr/lib/ePass2003-Linux-x64/redist/libcastle.so.1.0.0",
    "/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so",
    "/usr/lib/x86_64-linux-gnu/pkcs11/opensc-pkcs11.so",
    "/usr/lib/opensc-pkcs11.so",
    "/usr/lib64/opensc-pkcs11.so",
];

// Some native PKCS#11 modules do not tolerate concurrent initialize/finalize cycles.
static PKCS11_ACCESS: Mutex<()> = Mutex::new(());

#[derive(Debug, Error)]
pub enum ProviderError {
    #[error("PKCS#11 library not found")]
    LibraryNotFound,
    #[error("FIRMAPACHE_PKCS11 points to a file that does not exist: {0}")]
    InvalidEnvironmentPath(String),
    #[error("could not load PKCS#11 library at {path}: {source}")]
    LibraryLoad {
        path: String,
        #[source]
        source: cryptoki::error::Error,
    },
    #[error("could not initialize PKCS#11 library: {0}")]
    Initialize(#[source] cryptoki::error::Error),
    #[error("could not list PKCS#11 slots: {0}")]
    ListSlots(#[source] cryptoki::error::Error),
    #[error("could not list PKCS#11 tokens: {0}")]
    ListTokens(#[source] cryptoki::error::Error),
    #[error("could not read PKCS#11 token info for slot {slot_id}: {source}")]
    TokenInfo {
        slot_id: u64,
        #[source]
        source: cryptoki::error::Error,
    },
    #[error("could not open public PKCS#11 session for slot {slot_id}: {source}")]
    OpenSession {
        slot_id: u64,
        #[source]
        source: cryptoki::error::Error,
    },
    #[error("could not find PKCS#11 certificates for slot {slot_id}: {source}")]
    FindCertificates {
        slot_id: u64,
        #[source]
        source: cryptoki::error::Error,
    },
    #[error("could not read PKCS#11 certificate attributes for slot {slot_id}: {source}")]
    CertificateAttributes {
        slot_id: u64,
        #[source]
        source: cryptoki::error::Error,
    },
    #[error("PKCS#11 slot not found or has no token: {0}")]
    SlotNotFound(u64),
    #[error("unsupported signing mechanism: {0}")]
    UnsupportedMechanism(String),
    #[error("hash_base64 is not valid base64")]
    InvalidBase64Hash,
    #[error("certificate_id is not valid hexadecimal")]
    InvalidCertificateId,
    #[error("PKCS#11 login failed. Check PIN. No retry was attempted.")]
    LoginFailed,
    #[error("could not find PKCS#11 private keys: {0}")]
    PrivateKeySearch(#[source] cryptoki::error::Error),
    #[error("PKCS#11 private key not found")]
    PrivateKeyNotFound,
    #[error("Private key not found for selected certificate_id")]
    PrivateKeyNotFoundForCertificate,
    #[error("PKCS#11 signing operation failed: {0}")]
    SignFailed(#[source] cryptoki::error::Error),
    #[error("PKCS#11 logout failed after signing: {0}")]
    LogoutFailed(#[source] cryptoki::error::Error),
    #[error("PKCS#11 access lock is unavailable")]
    AccessLock,
}

pub fn detect_pkcs11_library(config: &AppConfig) -> Result<Pkcs11LibraryInfo, ProviderError> {
    let started = Instant::now();
    let env_path = env::var_os(PKCS11_LIBRARY_ENV)
        .map(|path| (PKCS11_LIBRARY_ENV, path))
        .or_else(|| {
            env::var_os(LEGACY_PKCS11_LIBRARY_ENV).map(|path| (LEGACY_PKCS11_LIBRARY_ENV, path))
        });
    if let Some((env_name, configured_path)) = env_path {
        let path = configured_path.to_string_lossy().into_owned();
        if !Path::new(&path).is_file() {
            warn!(
                path,
                source = env_name,
                signing_step = "detect_pkcs11_library",
                elapsed_ms = started.elapsed().as_millis() as u64,
                "configured PKCS#11 library does not exist"
            );
            return Err(ProviderError::InvalidEnvironmentPath(path));
        }

        info!(
            path,
            source = env_name,
            signing_step = "detect_pkcs11_library",
            elapsed_ms = started.elapsed().as_millis() as u64,
            "PKCS#11 library selected"
        );
        return Ok(Pkcs11LibraryInfo {
            found: true,
            path: Some(path),
            source: Some(env_name.to_owned()),
        });
    }

    if let Some(path) = config.pkcs11.library_path.as_deref() {
        if Path::new(path).is_file() {
            info!(
                path,
                source = "config",
                signing_step = "detect_pkcs11_library",
                elapsed_ms = started.elapsed().as_millis() as u64,
                "PKCS#11 library selected"
            );
            return Ok(Pkcs11LibraryInfo {
                found: true,
                path: Some(path.to_owned()),
                source: Some("config".to_owned()),
            });
        }

        warn!(
            path,
            source = "config",
            "configured PKCS#11 library does not exist; attempting autodetection"
        );
    }

    for path in COMMON_PKCS11_LIBRARY_PATHS {
        if Path::new(path).is_file() {
            info!(
                path,
                source = "auto",
                signing_step = "detect_pkcs11_library",
                elapsed_ms = started.elapsed().as_millis() as u64,
                "PKCS#11 library selected"
            );
            return Ok(Pkcs11LibraryInfo {
                found: true,
                path: Some(path.to_owned()),
                source: Some("auto".to_owned()),
            });
        }
    }

    warn!(
        signing_step = "detect_pkcs11_library",
        elapsed_ms = started.elapsed().as_millis() as u64,
        "PKCS#11 library not found in known locations"
    );
    Ok(Pkcs11LibraryInfo {
        found: false,
        path: None,
        source: None,
    })
}

pub fn list_tokens(config: &AppConfig) -> Result<Vec<TokenInfo>, ProviderError> {
    let started = Instant::now();
    let _access_guard = PKCS11_ACCESS
        .lock()
        .map_err(|_| ProviderError::AccessLock)?;

    let library_info = detect_pkcs11_library(config)?;
    let library_path = library_info.path.ok_or(ProviderError::LibraryNotFound)?;

    let pkcs11 = Pkcs11::new(&library_path).map_err(|source| ProviderError::LibraryLoad {
        path: library_path,
        source,
    })?;

    pkcs11
        .initialize(CInitializeArgs::OsThreads)
        .map_err(ProviderError::Initialize)?;

    let slots = pkcs11.get_all_slots().map_err(ProviderError::ListSlots)?;
    let slots_with_token = pkcs11
        .get_slots_with_token()
        .map_err(ProviderError::ListTokens)?;

    info!(
        slot_count = slots.len(),
        token_count = slots_with_token.len(),
        "PKCS#11 slots detected"
    );

    let tokens = slots
        .iter()
        .map(|slot| {
            let token_present = slots_with_token.contains(slot);
            if !token_present {
                return Ok(TokenInfo {
                    slot_id: slot.id(),
                    token_present: false,
                    label: None,
                    manufacturer: None,
                    model: None,
                    serial_number: None,
                });
            }

            let token =
                pkcs11
                    .get_token_info(*slot)
                    .map_err(|source| ProviderError::TokenInfo {
                        slot_id: slot.id(),
                        source,
                    })?;

            let label = normalize_token_text(token.label());
            let manufacturer = normalize_token_text(token.manufacturer_id());
            let model = normalize_token_text(token.model());
            let serial_number = normalize_token_text(token.serial_number());

            info!(
                slot_id = slot.id(),
                label, manufacturer, model, serial_number, "PKCS#11 token detected"
            );

            let token_info = TokenInfo {
                slot_id: slot.id(),
                token_present: true,
                label: Some(label),
                manufacturer: Some(manufacturer),
                model: Some(model),
                serial_number: Some(serial_number),
            };

            Ok(token_info)
        })
        .collect::<Result<Vec<_>, _>>()?;
    info!(
        signing_step = "list_tokens",
        elapsed_ms = started.elapsed().as_millis() as u64,
        token_count = tokens.len(),
        "PKCS#11 tokens listed"
    );
    Ok(tokens)
}

pub fn list_certificates(config: &AppConfig) -> Result<Vec<CertificateInfo>, ProviderError> {
    let started = Instant::now();
    let _access_guard = PKCS11_ACCESS
        .lock()
        .map_err(|_| ProviderError::AccessLock)?;

    let library_info = detect_pkcs11_library(config)?;
    let library_path = library_info.path.ok_or(ProviderError::LibraryNotFound)?;

    let pkcs11 = Pkcs11::new(&library_path).map_err(|source| ProviderError::LibraryLoad {
        path: library_path,
        source,
    })?;

    pkcs11
        .initialize(CInitializeArgs::OsThreads)
        .map_err(ProviderError::Initialize)?;

    let slots = pkcs11
        .get_slots_with_token()
        .map_err(ProviderError::ListTokens)?;
    info!(
        slot_count = slots.len(),
        "PKCS#11 token slots inspected for certificates"
    );

    let mut certificates = Vec::new();
    let search = [
        Attribute::Class(ObjectClass::CERTIFICATE),
        Attribute::CertificateType(CertificateType::X_509),
    ];

    for slot in slots {
        let session =
            pkcs11
                .open_ro_session(slot)
                .map_err(|source| ProviderError::OpenSession {
                    slot_id: slot.id(),
                    source,
                })?;
        let objects =
            session
                .find_objects(&search)
                .map_err(|source| ProviderError::FindCertificates {
                    slot_id: slot.id(),
                    source,
                })?;

        info!(
            slot_id = slot.id(),
            certificate_count = objects.len(),
            "PKCS#11 certificate objects detected"
        );

        for object in objects {
            let attributes = session
                .get_attributes(
                    object,
                    &[
                        AttributeType::Id,
                        AttributeType::Label,
                        AttributeType::Value,
                    ],
                )
                .map_err(|source| ProviderError::CertificateAttributes {
                    slot_id: slot.id(),
                    source,
                })?;
            let mut certificate = CertificateInfo {
                slot_id: slot.id(),
                id: None,
                label: None,
                certificate_der_base64: None,
                subject: None,
                issuer: None,
                serial_number: None,
                not_before: None,
                not_after: None,
            };
            let mut der_value = None;

            for attribute in attributes {
                match attribute {
                    Attribute::Id(id) => certificate.id = Some(bytes_to_hex(&id)),
                    Attribute::Label(label) => {
                        certificate.label =
                            Some(normalize_token_text(&String::from_utf8_lossy(&label)));
                    }
                    Attribute::Value(value) => der_value = Some(value),
                    _ => {}
                }
            }

            if let Some(der) = der_value {
                certificate.certificate_der_base64 = Some(STANDARD.encode(&der));
                match parse_x509_certificate(&der) {
                    Ok((_remaining, parsed)) => {
                        certificate.subject = Some(parsed.subject().to_string());
                        certificate.issuer = Some(parsed.issuer().to_string());
                        certificate.serial_number =
                            Some(parsed.tbs_certificate.raw_serial_as_string());
                        certificate.not_before =
                            Some(format_certificate_time(parsed.validity().not_before));
                        certificate.not_after =
                            Some(format_certificate_time(parsed.validity().not_after));
                    }
                    Err(error) => {
                        warn!(
                            slot_id = slot.id(),
                            id = ?certificate.id,
                            error = ?error,
                            "could not parse X.509 certificate value"
                        );
                    }
                }
            } else {
                warn!(
                    slot_id = slot.id(),
                    id = ?certificate.id,
                    "PKCS#11 certificate has no readable value"
                );
            }

            certificates.push(certificate);
        }
    }

    info!(
        signing_step = "list_certificates",
        elapsed_ms = started.elapsed().as_millis() as u64,
        certificate_count = certificates.len(),
        "PKCS#11 certificates listed"
    );
    Ok(certificates)
}

pub fn sign_hash(
    config: &AppConfig,
    request: SignHashRequest,
) -> Result<SignHashResponse, ProviderError> {
    let started = Instant::now();
    let SignHashRequest {
        slot_id,
        pin,
        hash_base64,
        mechanism,
        certificate_id,
    } = request;
    let algorithm = mechanism.unwrap_or_else(|| "RSA_PKCS".to_owned());
    if algorithm != "RSA_PKCS" {
        return Err(ProviderError::UnsupportedMechanism(algorithm));
    }

    let hash = STANDARD
        .decode(hash_base64.as_bytes())
        .map_err(|_| ProviderError::InvalidBase64Hash)?;
    let selected_certificate_id = certificate_id
        .as_deref()
        .map(parse_certificate_id)
        .transpose()?;
    let response_certificate_id = selected_certificate_id.as_deref().map(bytes_to_hex);
    info!(
        slot_id,
        certificate_id_selected = selected_certificate_id.is_some(),
        "PKCS#11 signing request prepared"
    );
    let auth_pin = AuthPin::new(pin);

    let _access_guard = PKCS11_ACCESS
        .lock()
        .map_err(|_| ProviderError::AccessLock)?;
    let library_info = detect_pkcs11_library(config)?;
    let library_path = library_info.path.ok_or(ProviderError::LibraryNotFound)?;
    let pkcs11 = Pkcs11::new(&library_path).map_err(|source| ProviderError::LibraryLoad {
        path: library_path,
        source,
    })?;

    pkcs11
        .initialize(CInitializeArgs::OsThreads)
        .map_err(ProviderError::Initialize)?;

    let slot = pkcs11
        .get_slots_with_token()
        .map_err(ProviderError::ListTokens)?
        .into_iter()
        .find(|slot| slot.id() == slot_id)
        .ok_or(ProviderError::SlotNotFound(slot_id))?;

    let session = match pkcs11.open_rw_session(slot) {
        Ok(session) => session,
        Err(_) => pkcs11
            .open_ro_session(slot)
            .map_err(|source| ProviderError::OpenSession { slot_id, source })?,
    };

    session
        .login(UserType::User, Some(&auth_pin))
        .map_err(|_| ProviderError::LoginFailed)?;

    let signing_result = (|| {
        let private_key = match selected_certificate_id.as_deref() {
            Some(certificate_id) => find_private_key_for_certificate(&session, certificate_id)?,
            None => {
                warn!(
                    slot_id,
                    "certificate_id was not specified; using automatic private key selection"
                );
                find_private_key(&session)?
            }
        };
        let signature = session
            .sign(&Mechanism::RsaPkcs, private_key, &hash)
            .map_err(ProviderError::SignFailed)?;

        info!(
            slot_id,
            certificate_id_selected = selected_certificate_id.is_some(),
            algorithm,
            signing_step = "sign_hash",
            elapsed_ms = started.elapsed().as_millis() as u64,
            "PKCS#11 hash signature created"
        );
        Ok(SignHashResponse {
            slot_id,
            signature_base64: STANDARD.encode(signature),
            algorithm,
            certificate_id: response_certificate_id,
        })
    })();

    let logout_result = session.logout().map_err(ProviderError::LogoutFailed);
    match (signing_result, logout_result) {
        (Err(error), _) => Err(error),
        (Ok(_), Err(error)) => Err(error),
        (Ok(response), Ok(())) => Ok(response),
    }
}

pub fn sign_rs256(
    config: &AppConfig,
    slot_id: u64,
    certificate_id: String,
    pin: String,
    signing_input_bytes: &[u8],
) -> Result<Vec<u8>, ProviderError> {
    let started = Instant::now();
    let selected_certificate_id = parse_certificate_id(&certificate_id)?;
    let auth_pin = AuthPin::new(pin);

    let _access_guard = PKCS11_ACCESS
        .lock()
        .map_err(|_| ProviderError::AccessLock)?;
    let library_info = detect_pkcs11_library(config)?;
    let library_path = library_info.path.ok_or(ProviderError::LibraryNotFound)?;
    let pkcs11 = Pkcs11::new(&library_path).map_err(|source| ProviderError::LibraryLoad {
        path: library_path,
        source,
    })?;

    pkcs11
        .initialize(CInitializeArgs::OsThreads)
        .map_err(ProviderError::Initialize)?;

    let slot = pkcs11
        .get_slots_with_token()
        .map_err(ProviderError::ListTokens)?
        .into_iter()
        .find(|slot| slot.id() == slot_id)
        .ok_or(ProviderError::SlotNotFound(slot_id))?;

    let session = match pkcs11.open_rw_session(slot) {
        Ok(session) => session,
        Err(_) => pkcs11
            .open_ro_session(slot)
            .map_err(|source| ProviderError::OpenSession { slot_id, source })?,
    };

    session
        .login(UserType::User, Some(&auth_pin))
        .map_err(|_| ProviderError::LoginFailed)?;

    let signing_result = (|| {
        let private_key = find_private_key_for_certificate(&session, &selected_certificate_id)?;

        match session.sign(&Mechanism::Sha256RsaPkcs, private_key, signing_input_bytes) {
            Ok(signature) => {
                info!(
                    slot_id,
                    signing_step = "sign_rs256",
                    mechanism = "CKM_SHA256_RSA_PKCS",
                    elapsed_ms = started.elapsed().as_millis() as u64,
                    "PKCS#11 RS256 signature created"
                );
                Ok(signature)
            }
            Err(error) => {
                warn!(
                    slot_id,
                    error = %error,
                    signing_step = "sign_rs256",
                    mechanism = "CKM_SHA256_RSA_PKCS",
                    "PKCS#11 RS256 direct mechanism failed; trying DigestInfo fallback"
                );
                let digest_info = sha256_digest_info(signing_input_bytes);
                let signature = session
                    .sign(&Mechanism::RsaPkcs, private_key, &digest_info)
                    .map_err(ProviderError::SignFailed)?;
                info!(
                    slot_id,
                    signing_step = "sign_rs256",
                    mechanism = "CKM_RSA_PKCS_DIGEST_INFO",
                    elapsed_ms = started.elapsed().as_millis() as u64,
                    "PKCS#11 RS256 signature created with DigestInfo fallback"
                );
                Ok(signature)
            }
        }
    })();

    let logout_result = session.logout().map_err(ProviderError::LogoutFailed);
    match (signing_result, logout_result) {
        (Err(error), _) => Err(error),
        (Ok(_), Err(error)) => Err(error),
        (Ok(signature), Ok(())) => Ok(signature),
    }
}

fn find_private_key_for_certificate(
    session: &Session,
    certificate_id: &[u8],
) -> Result<ObjectHandle, ProviderError> {
    session
        .find_objects(&[
            Attribute::Class(ObjectClass::PRIVATE_KEY),
            Attribute::Id(certificate_id.to_vec()),
        ])
        .map_err(ProviderError::PrivateKeySearch)?
        .first()
        .copied()
        .ok_or(ProviderError::PrivateKeyNotFoundForCertificate)
}

fn find_private_key(session: &Session) -> Result<ObjectHandle, ProviderError> {
    let private_keys = session
        .find_objects(&[Attribute::Class(ObjectClass::PRIVATE_KEY)])
        .map_err(ProviderError::PrivateKeySearch)?;
    let first_private_key = private_keys
        .first()
        .copied()
        .ok_or(ProviderError::PrivateKeyNotFound)?;

    let certificates = match session.find_objects(&[
        Attribute::Class(ObjectClass::CERTIFICATE),
        Attribute::CertificateType(CertificateType::X_509),
    ]) {
        Ok(certificates) => certificates,
        Err(error) => {
            warn!(error = %error, "could not match private key to certificate; using first key");
            return Ok(first_private_key);
        }
    };

    let certificate_ids: Vec<Vec<u8>> = certificates
        .into_iter()
        .filter_map(|certificate| read_object_id(session, certificate))
        .collect();

    for private_key in private_keys {
        if read_object_id(session, private_key)
            .is_some_and(|private_key_id| certificate_ids.contains(&private_key_id))
        {
            return Ok(private_key);
        }
    }

    Ok(first_private_key)
}

fn read_object_id(session: &Session, object: ObjectHandle) -> Option<Vec<u8>> {
    match session.get_attributes(object, &[AttributeType::Id]) {
        Ok(attributes) => attributes
            .into_iter()
            .find_map(|attribute| match attribute {
                Attribute::Id(id) => Some(id),
                _ => None,
            }),
        Err(error) => {
            warn!(error = %error, "could not read CKA_ID while matching signing key");
            None
        }
    }
}

fn normalize_token_text(value: &str) -> String {
    value
        .trim_end_matches(|character| character == '\0' || character == ' ')
        .to_owned()
}

fn bytes_to_hex(value: &[u8]) -> String {
    value.iter().map(|byte| format!("{byte:02X}")).collect()
}

fn parse_certificate_id(value: &str) -> Result<Vec<u8>, ProviderError> {
    if value.is_empty() || value.len() % 2 != 0 {
        return Err(ProviderError::InvalidCertificateId);
    }

    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            std::str::from_utf8(pair)
                .map_err(|_| ProviderError::InvalidCertificateId)
                .and_then(|hex| {
                    u8::from_str_radix(hex, 16).map_err(|_| ProviderError::InvalidCertificateId)
                })
        })
        .collect()
}

fn sha256_digest_info(value: &[u8]) -> Vec<u8> {
    let hash = Sha256::digest(value);
    let mut digest_info = Vec::with_capacity(SHA256_DIGEST_INFO_PREFIX.len() + hash.len());
    digest_info.extend_from_slice(&SHA256_DIGEST_INFO_PREFIX);
    digest_info.extend_from_slice(&hash);
    digest_info
}

fn format_certificate_time(value: ASN1Time) -> String {
    let date_time = value.to_datetime();

    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        date_time.year(),
        u8::from(date_time.month()),
        date_time.day(),
        date_time.hour(),
        date_time.minute(),
        date_time.second()
    )
}
