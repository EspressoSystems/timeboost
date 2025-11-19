use std::{env, sync::Once};

use tracing_subscriber::EnvFilter;

static LOG_INIT: Once = Once::new();

pub fn init_logging() {
    LOG_INIT.call_once(|| {
        if env::var("RUST_LOG_FORMAT") == Ok("json".to_string()) {
            tracing_subscriber::fmt()
                .with_env_filter(EnvFilter::from_default_env())
                .json()
                .init();
        } else {
            tracing_subscriber::fmt()
                .with_env_filter(EnvFilter::from_default_env())
                .with_ansi(use_color())
                .init();
        }
    });
}

fn use_color() -> bool {
    env::var("NO_COLOR").map(|v| v.is_empty()).unwrap_or(true)
}
