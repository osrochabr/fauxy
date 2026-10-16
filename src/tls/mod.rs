//! TLS: local CA, system trust store integration and the client configuration
//! used to reach real servers.

mod ca;
mod trust;
mod upstream;

pub use ca::{CaError, LocalCa, der_to_pem, write_bundle};
pub use trust::{
    TrustCommand, TrustStore, find_program, install_commands, shell_quote, uninstall_commands,
};
pub use upstream::{UpstreamError, client_config, crypto_provider};
