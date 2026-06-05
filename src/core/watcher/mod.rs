use std::{ffi::CString, time::Duration};

use pcsc::{Context, ReaderState, Scope, State};
use thiserror::Error;
use tracing::{debug, info};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TokenWatcherEventKind {
    Insert,
    Remove,
    ReaderAdded,
    ReaderRemoved,
    Change,
}

impl TokenWatcherEventKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Insert => "insert",
            Self::Remove => "remove",
            Self::ReaderAdded => "reader_added",
            Self::ReaderRemoved => "reader_removed",
            Self::Change => "change",
        }
    }
}

#[derive(Debug, Clone)]
pub struct TokenWatcherEvent {
    pub kind: TokenWatcherEventKind,
    pub reader: Option<String>,
}

pub struct PcscTokenWatcher {
    context: Context,
    readers: Vec<ReaderState>,
    reader_names: Vec<String>,
}

impl PcscTokenWatcher {
    pub fn new() -> Result<Self, TokenWatcherError> {
        let context = Context::establish(Scope::User)?;
        let mut watcher = Self {
            context,
            readers: Vec::new(),
            reader_names: Vec::new(),
        };
        watcher.rebuild_reader_states()?;
        info!(
            watcher_started = true,
            watcher_backend = "pcsc",
            reader_count = watcher.reader_names.len(),
            "PC/SC token watcher started"
        );
        Ok(watcher)
    }

    pub fn wait_for_events(&mut self) -> Result<Vec<TokenWatcherEvent>, TokenWatcherError> {
        self.context.get_status_change(None, &mut self.readers)?;
        let mut events = Vec::new();
        let mut readers_changed = false;

        for state in &mut self.readers {
            let name = state.name().to_string_lossy().into_owned();
            let previous = state.current_state();
            let current = state.event_state();
            if !current.contains(State::CHANGED) {
                state.sync_current_state();
                continue;
            }

            if state.name() == pcsc::PNP_NOTIFICATION() {
                readers_changed = true;
                state.sync_current_state();
                continue;
            }

            let kind = if !previous.contains(State::PRESENT) && current.contains(State::PRESENT) {
                Some(TokenWatcherEventKind::Insert)
            } else if previous.contains(State::PRESENT) && current.contains(State::EMPTY) {
                Some(TokenWatcherEventKind::Remove)
            } else if current.intersects(State::UNKNOWN | State::UNAVAILABLE) {
                Some(TokenWatcherEventKind::ReaderRemoved)
            } else {
                Some(TokenWatcherEventKind::Change)
            };

            if let Some(kind) = kind {
                if kind == TokenWatcherEventKind::Change {
                    debug!(
                        watcher_event = kind.as_str(),
                        reader = %name,
                        "PC/SC watcher observed unchanged reader state"
                    );
                } else {
                    info!(
                        watcher_event = kind.as_str(),
                        reader = %name,
                        "PC/SC watcher event"
                    );
                }
                events.push(TokenWatcherEvent {
                    kind,
                    reader: Some(name),
                });
            }
            state.sync_current_state();
        }

        if readers_changed {
            let previous_names = self.reader_names.clone();
            self.rebuild_reader_states()?;
            for reader in self
                .reader_names
                .iter()
                .filter(|reader| !previous_names.contains(reader))
            {
                info!(
                    watcher_event = "reader_added",
                    reader = %reader,
                    "PC/SC reader added"
                );
                events.push(TokenWatcherEvent {
                    kind: TokenWatcherEventKind::ReaderAdded,
                    reader: Some(reader.clone()),
                });
            }
            for reader in previous_names
                .iter()
                .filter(|reader| !self.reader_names.contains(reader))
            {
                info!(
                    watcher_event = "reader_removed",
                    reader = %reader,
                    "PC/SC reader removed"
                );
                events.push(TokenWatcherEvent {
                    kind: TokenWatcherEventKind::ReaderRemoved,
                    reader: Some(reader.clone()),
                });
            }
        }

        Ok(events)
    }

    fn rebuild_reader_states(&mut self) -> Result<(), TokenWatcherError> {
        let mut readers = vec![ReaderState::new(
            pcsc::PNP_NOTIFICATION().to_owned(),
            State::UNAWARE,
        )];
        let reader_names = self
            .context
            .list_readers_owned()?
            .into_iter()
            .map(|reader| reader.to_string_lossy().into_owned())
            .collect::<Vec<_>>();

        for reader in &reader_names {
            readers.push(ReaderState::new(
                CString::new(reader.as_str()).map_err(|_| TokenWatcherError::InvalidReaderName)?,
                State::UNAWARE,
            ));
        }

        let _ = self
            .context
            .get_status_change(Some(Duration::from_millis(0)), &mut readers);
        for reader in &mut readers {
            reader.sync_current_state();
        }

        self.readers = readers;
        self.reader_names = reader_names;
        Ok(())
    }
}

#[derive(Debug, Error)]
pub enum TokenWatcherError {
    #[error("PC/SC error: {0}")]
    Pcsc(#[from] pcsc::Error),
    #[error("PC/SC reader name contains an interior NUL byte")]
    InvalidReaderName,
}
