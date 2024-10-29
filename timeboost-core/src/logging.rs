use std::sync::Once;

use tracing_subscriber::{fmt::format::FmtSpan, EnvFilter};

static LOG_INIT: Once = Once::new();

pub fn init_logging() {
    LOG_INIT.call_once(|| {
        if std::env::var("RUST_LOG_FORMAT") == Ok("json".to_string()) {
            tracing_subscriber::fmt()
                .with_env_filter(EnvFilter::from_default_env())
                .with_span_events(FmtSpan::NEW)
                .json()
                .init();
        } else {
            tracing_subscriber::fmt()
                .with_env_filter(EnvFilter::from_default_env())
                .with_span_events(FmtSpan::NEW)
                .init();
        }
    });
}
