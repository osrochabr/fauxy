//! fauxy: a local HTTP/HTTPS proxy that answers selected requests with mocks
//! declared in YAML files.
//!
//! The binary is a thin wrapper over [`cli::main`]; the modules are public so
//! the integration tests can drive the proxy and the daemon in-process.

pub mod cli;
pub mod config;
pub mod control;
pub mod daemon;
pub mod envvars;
pub mod events;
pub mod java;
pub mod paths;
pub mod proxy;
pub mod rules;
pub mod state;
pub mod sys;
pub mod tls;
pub mod tui;
