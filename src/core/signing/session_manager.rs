use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
    time::Duration,
};

use chrono::Utc;
use thiserror::Error;
use tokio::sync::oneshot;
use tokio::time::timeout;
use tracing::info;
use uuid::Uuid;

use crate::models::{
    compatible::{CompatibleSignRequest, CompatibleSignResponse},
    signing::{SigningSession, SigningSessionResult, SigningSessionStatus},
};

use super::compatible::{self, CompatibleSignError};

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

    pub fn approve(&self, id: Uuid) -> Result<CompatibleSignResponse, SigningSessionError> {
        let (response, sender, format, file_count) = {
            let mut sessions = self
                .sessions
                .write()
                .map_err(|_| SigningSessionError::StateLock)?;
            let state = sessions.get_mut(&id).ok_or(SigningSessionError::NotFound)?;
            ensure_pending(&state.session)?;

            state.session.status = SigningSessionStatus::Approved;
            (
                compatible::response_for_files(&state.session.files),
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
