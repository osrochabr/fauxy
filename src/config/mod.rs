//! Configuration files: global settings (`config.yaml`) and mock rules.

mod load;
pub mod schema;
pub mod templates;

pub use load::{
    ConfigError, ConfigErrors, DEFAULT_LISTEN, LoadedConfig, MOCK_EXTENSIONS, load, load_file,
    parse_listen,
};
