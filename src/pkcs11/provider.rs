use std::{env, path::Path, sync::Mutex};

use cryptoki::{context::CInitializeArgs, context::Pkcs11};
use thiserror::Error;
use tracing::{info, warn};

use crate::models::pkcs11::{Pkcs11LibraryInfo, TokenInfo};

const PKCS11_LIBRARY_ENV: &str = "MINI_FIRMADOR_PKCS11";

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
    #[error("MINI_FIRMADOR_PKCS11 points to a file that does not exist: {0}")]
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
    #[error("PKCS#11 access lock is unavailable")]
    AccessLock,
}

pub fn detect_pkcs11_library() -> Result<Pkcs11LibraryInfo, ProviderError> {
    if let Some(configured_path) = env::var_os(PKCS11_LIBRARY_ENV) {
        let path = configured_path.to_string_lossy().into_owned();
        if !Path::new(&path).is_file() {
            warn!(
                path,
                source = "env",
                "configured PKCS#11 library does not exist"
            );
            return Err(ProviderError::InvalidEnvironmentPath(path));
        }

        info!(path, source = "env", "PKCS#11 library selected");
        return Ok(Pkcs11LibraryInfo {
            found: true,
            path: Some(path),
            source: Some("env".to_owned()),
        });
    }

    for path in COMMON_PKCS11_LIBRARY_PATHS {
        if Path::new(path).is_file() {
            info!(path, source = "auto", "PKCS#11 library selected");
            return Ok(Pkcs11LibraryInfo {
                found: true,
                path: Some(path.to_owned()),
                source: Some("auto".to_owned()),
            });
        }
    }

    warn!("PKCS#11 library not found in known locations");
    Ok(Pkcs11LibraryInfo {
        found: false,
        path: None,
        source: None,
    })
}

pub fn list_tokens() -> Result<Vec<TokenInfo>, ProviderError> {
    let _access_guard = PKCS11_ACCESS
        .lock()
        .map_err(|_| ProviderError::AccessLock)?;

    let library_info = detect_pkcs11_library()?;
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

    slots
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
        .collect()
}

fn normalize_token_text(value: &str) -> String {
    value
        .trim_end_matches(|character| character == '\0' || character == ' ')
        .to_owned()
}
