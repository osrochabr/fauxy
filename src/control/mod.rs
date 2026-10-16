//! Control API (HTTP/1.1 + JSON over a Unix socket) used by the CLI and the
//! TUI to talk to the daemon.

pub mod api;
mod client;
pub(crate) mod server;

pub use api::{ApiError, EventsPage, ReloadResult, RuleInfo, StatusInfo};
pub use client::{ClientError, ControlClient, DEFAULT_TIMEOUT};
pub use server::{ControlContext, ControlServer, MAX_EVENTS_PER_PAGE, ReloadFn, StatusFn, handle};
