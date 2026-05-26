use std::{
    fs,
    path::{Path, PathBuf},
};

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

use anyhow::{Context, Result};
use axum_server::tls_rustls::RustlsConfig;
use rcgen::{CertifiedKey, generate_simple_self_signed};
use tracing::info;

use crate::config::AppConfig;

const CERTIFICATES_DIRECTORY: &str = "certs";
const CERTIFICATE_FILE: &str = "localhost.crt";
const PRIVATE_KEY_FILE: &str = "localhost.key";

pub struct CertificatePaths {
    pub certificate: PathBuf,
    pub private_key: PathBuf,
}

impl CertificatePaths {
    fn resolve() -> Result<Self> {
        let directory = AppConfig::config_directory()
            .context("could not determine local TLS certificate directory")?
            .join(CERTIFICATES_DIRECTORY);

        Ok(Self {
            certificate: directory.join(CERTIFICATE_FILE),
            private_key: directory.join(PRIVATE_KEY_FILE),
        })
    }
}

pub async fn load_or_generate_config() -> Result<RustlsConfig> {
    let paths = CertificatePaths::resolve()?;
    ensure_certificate_files(&paths)?;
    info!(
        certificate = %paths.certificate.display(),
        private_key = %paths.private_key.display(),
        "local TLS certificate selected"
    );

    RustlsConfig::from_pem_file(&paths.certificate, &paths.private_key)
        .await
        .context("could not load local TLS certificate")
}

fn ensure_certificate_files(paths: &CertificatePaths) -> Result<()> {
    if paths.certificate.is_file() && paths.private_key.is_file() {
        return Ok(());
    }

    let directory = paths
        .certificate
        .parent()
        .context("could not determine local TLS certificate parent directory")?;
    fs::create_dir_all(directory).with_context(|| {
        format!(
            "could not create certificate directory {}",
            directory.display()
        )
    })?;

    let CertifiedKey { cert, signing_key } =
        generate_simple_self_signed(vec!["localhost".to_owned(), "127.0.0.1".to_owned()])
            .context("could not generate localhost self-signed certificate")?;

    write_file(&paths.certificate, cert.pem().as_bytes())
        .context("could not write localhost certificate")?;
    write_file(&paths.private_key, signing_key.serialize_pem().as_bytes())
        .context("could not write localhost private key")?;

    #[cfg(unix)]
    fs::set_permissions(&paths.private_key, fs::Permissions::from_mode(0o600))
        .context("could not secure localhost private key permissions")?;

    info!(
        certificate = %paths.certificate.display(),
        private_key = %paths.private_key.display(),
        "self-signed localhost TLS certificate created"
    );

    Ok(())
}

fn write_file(path: &Path, contents: &[u8]) -> Result<()> {
    fs::write(path, contents).with_context(|| format!("could not write {}", path.display()))
}
