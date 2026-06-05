use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
    time::{Duration, Instant},
};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use chrono::Utc;
use thiserror::Error;
use tokio::sync::oneshot;
use tokio::time::timeout;
use tracing::info;
use uuid::Uuid;

use crate::{
    config::AppConfig,
    core::{
        cache::TokenCertificateCache,
        pdf::{self, PdfError},
    },
    models::{
        compatible::{CompatibleOutputFile, CompatibleSignRequest, CompatibleSignResponse},
        signing::{
            ApproveSigningSessionInput, SigningSession, SigningSessionResult, SigningSessionStatus,
        },
    },
};

use super::{
    compatible::{self, CompatibleSignError},
    jws::{self, JwsSignError},
};

const SIGNING_SESSION_TIMEOUT: Duration = Duration::from_secs(5 * 60);

struct SigningSessionState {
    session: SigningSession,
    sender: Option<oneshot::Sender<SigningSessionResult>>,
}

#[derive(Clone)]
pub struct SigningSessionManager {
    sessions: Arc<RwLock<HashMap<Uuid, SigningSessionState>>>,
    request_timeout: Duration,
}

impl SigningSessionManager {
    pub fn new() -> Self {
        Self {
            sessions: Arc::new(RwLock::new(HashMap::new())),
            request_timeout: SIGNING_SESSION_TIMEOUT,
        }
    }

    pub async fn create_and_wait(
        &self,
        request: CompatibleSignRequest,
    ) -> Result<SigningSessionResult, SigningSessionError> {
        let prepared = compatible::prepare_sign_request(request)?;
        let session = SigningSession {
            id: Uuid::new_v4(),
            files: prepared.files,
            format: prepared.format,
            language: prepared.language,
            status: SigningSessionStatus::Pending,
            created_at: Utc::now(),
        };
        let id = session.id;
        let file_count = session.files.len();
        let format = session.format.clone();
        let (sender, receiver) = oneshot::channel();

        self.cleanup_resolved_sessions()?;
        self.sessions
            .write()
            .map_err(|_| SigningSessionError::StateLock)?
            .insert(
                id,
                SigningSessionState {
                    session,
                    sender: Some(sender),
                },
            );
        info!(session_id = %id, %format, file_count, status = "pending", "signing session created");

        match timeout(self.request_timeout, receiver).await {
            Ok(Ok(result)) => Ok(result),
            Ok(Err(_)) | Err(_) => {
                self.expire(id)?;
                Ok(SigningSessionResult::Expired)
            }
        }
    }

    pub fn list(&self) -> Result<Vec<SigningSession>, SigningSessionError> {
        self.cleanup_resolved_sessions()?;
        let mut sessions = self
            .sessions
            .read()
            .map_err(|_| SigningSessionError::StateLock)?
            .values()
            .map(|state| state.session.clone())
            .collect::<Vec<_>>();
        sessions.sort_by_key(|session| session.created_at);
        Ok(sessions)
    }

    pub fn get(&self, id: Uuid) -> Result<SigningSession, SigningSessionError> {
        self.cleanup_resolved_sessions()?;
        self.sessions
            .read()
            .map_err(|_| SigningSessionError::StateLock)?
            .get(&id)
            .map(|state| state.session.clone())
            .ok_or(SigningSessionError::NotFound)
    }

    pub fn approve_with_signature(
        &self,
        id: Uuid,
        config: &AppConfig,
        input: ApproveSigningSessionInput,
        cache: &TokenCertificateCache,
    ) -> Result<CompatibleSignResponse, SigningSessionError> {
        let started = Instant::now();
        let session = {
            let sessions = self
                .sessions
                .read()
                .map_err(|_| SigningSessionError::StateLock)?;
            let state = sessions.get(&id).ok_or(SigningSessionError::NotFound)?;
            ensure_pending(&state.session)?;
            state.session.clone()
        };

        let file_count = session.files.len();
        let format = session.format.clone();
        let response = sign_prepared_files(config, cache, &session.files, &session.format, input)?;
        info!(
            session_id = %id,
            %format,
            file_count,
            signing_step = "approve_signing_session",
            elapsed_ms = started.elapsed().as_millis() as u64,
            "signing session approved"
        );
        self.resolve_signed(id, response)
    }

    pub fn approve_temporarily(
        &self,
        id: Uuid,
    ) -> Result<CompatibleSignResponse, SigningSessionError> {
        let response = {
            let sessions = self
                .sessions
                .read()
                .map_err(|_| SigningSessionError::StateLock)?;
            let state = sessions.get(&id).ok_or(SigningSessionError::NotFound)?;
            ensure_pending(&state.session)?;
            compatible::response_for_files(&state.session.files)
        };
        self.resolve_signed(id, response)
    }

    fn resolve_signed(
        &self,
        id: Uuid,
        response: CompatibleSignResponse,
    ) -> Result<CompatibleSignResponse, SigningSessionError> {
        let (response, sender, format, file_count) = {
            let mut sessions = self
                .sessions
                .write()
                .map_err(|_| SigningSessionError::StateLock)?;
            let state = sessions.get_mut(&id).ok_or(SigningSessionError::NotFound)?;
            ensure_pending(&state.session)?;

            state.session.status = SigningSessionStatus::Approved;
            (
                response,
                state.sender.take(),
                state.session.format.clone(),
                state.session.files.len(),
            )
        };
        let sender = sender.ok_or(SigningSessionError::AlreadyResolved)?;
        sender
            .send(SigningSessionResult::Signed(response.clone()))
            .map_err(|_| SigningSessionError::AlreadyResolved)?;
        info!(session_id = %id, %format, file_count, status = "approved", "signing session resolved");
        Ok(response)
    }

    pub fn reject(&self, id: Uuid) -> Result<SigningSession, SigningSessionError> {
        let (session, sender) = {
            let mut sessions = self
                .sessions
                .write()
                .map_err(|_| SigningSessionError::StateLock)?;
            let state = sessions.get_mut(&id).ok_or(SigningSessionError::NotFound)?;
            ensure_pending(&state.session)?;

            state.session.status = SigningSessionStatus::Rejected;
            (state.session.clone(), state.sender.take())
        };
        let sender = sender.ok_or(SigningSessionError::AlreadyResolved)?;
        sender
            .send(SigningSessionResult::Rejected)
            .map_err(|_| SigningSessionError::AlreadyResolved)?;
        info!(
            session_id = %id,
            format = %session.format,
            file_count = session.files.len(),
            status = "rejected",
            "signing session resolved"
        );
        Ok(session)
    }

    fn expire(&self, id: Uuid) -> Result<(), SigningSessionError> {
        let expired = {
            let mut sessions = self
                .sessions
                .write()
                .map_err(|_| SigningSessionError::StateLock)?;
            let Some(state) = sessions.get_mut(&id) else {
                return Ok(());
            };
            if state.session.status != SigningSessionStatus::Pending {
                return Ok(());
            }

            state.session.status = SigningSessionStatus::Expired;
            state.sender.take();
            Some((state.session.format.clone(), state.session.files.len()))
        };

        if let Some((format, file_count)) = expired {
            info!(session_id = %id, %format, file_count, status = "expired", "signing session resolved");
        }
        Ok(())
    }

    fn cleanup_resolved_sessions(&self) -> Result<(), SigningSessionError> {
        let cutoff = chrono::Duration::from_std(self.request_timeout)
            .map_err(|_| SigningSessionError::StateLock)?;
        let now = Utc::now();
        self.sessions
            .write()
            .map_err(|_| SigningSessionError::StateLock)?
            .retain(|_, state| {
                state.session.status == SigningSessionStatus::Pending
                    || now.signed_duration_since(state.session.created_at) < cutoff
            });
        Ok(())
    }
}

pub fn sign_prepared_files(
    config: &AppConfig,
    cache: &TokenCertificateCache,
    files: &[crate::models::signing::SigningSessionFile],
    format: &str,
    input: ApproveSigningSessionInput,
) -> Result<CompatibleSignResponse, SigningSessionError> {
    match format {
        "jws" => Ok(jws::sign_files_with_cache(config, files, input, cache)?),
        "pdf" => sign_pdf_session_files(config, cache, files, input),
        format => Err(SigningSessionError::Compatible(
            CompatibleSignError::UnsupportedFormat(format.to_owned()),
        )),
    }
}

fn ensure_pending(session: &SigningSession) -> Result<(), SigningSessionError> {
    match session.status {
        SigningSessionStatus::Pending => Ok(()),
        SigningSessionStatus::Expired => Err(SigningSessionError::Expired),
        SigningSessionStatus::Approved | SigningSessionStatus::Rejected => {
            Err(SigningSessionError::AlreadyResolved)
        }
    }
}

#[derive(Debug, Error)]
pub enum SigningSessionError {
    #[error(transparent)]
    Compatible(#[from] CompatibleSignError),
    #[error(transparent)]
    Jws(#[from] JwsSignError),
    #[error(transparent)]
    Pdf(#[from] PdfError),
    #[error("Session not found")]
    NotFound,
    #[error("Session already resolved")]
    AlreadyResolved,
    #[error("Signing request expired")]
    Expired,
    #[error("User cancelled signing operation")]
    Rejected,
    #[error("Signing session state lock is unavailable")]
    StateLock,
}

fn sign_pdf_session_files(
    config: &AppConfig,
    cache: &TokenCertificateCache,
    files: &[crate::models::signing::SigningSessionFile],
    input: ApproveSigningSessionInput,
) -> Result<CompatibleSignResponse, SigningSessionError> {
    let mut output = Vec::with_capacity(files.len());
    for file in files {
        let pdf_bytes = STANDARD
            .decode(file.content_base64.as_bytes())
            .map_err(|_| CompatibleSignError::InvalidBase64)?;
        let signed_pdf = pdf::signing::sign_pdf_bytes(
            config,
            cache,
            &pdf_bytes,
            file.name.clone(),
            input.clone(),
        )?;
        output.push(CompatibleOutputFile {
            base64: STANDARD.encode(signed_pdf),
            name: file.name.clone(),
        });
    }

    Ok(CompatibleSignResponse { files: output })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::compatible::{CompatibleInputFile, CompatibleSignRequest};

    #[tokio::test]
    async fn waiting_session_expires_after_timeout() {
        let manager = SigningSessionManager {
            sessions: Arc::new(RwLock::new(HashMap::new())),
            request_timeout: Duration::from_millis(1),
        };
        let request = CompatibleSignRequest {
            archivo: vec![CompatibleInputFile {
                base64: "e30=".to_owned(),
                name: "test.json".to_owned(),
            }],
            format: "jws".to_owned(),
            language: None,
        };

        let result = manager
            .create_and_wait(request)
            .await
            .expect("session timeout should be represented as a result");

        assert!(matches!(result, SigningSessionResult::Expired));
    }
}
