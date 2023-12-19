//! Shared setup code for integration tests
use std::sync::Once;
use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter, Registry};

static INIT: Once = Once::new();

pub(crate) fn init_logging() {
    INIT.call_once(|| {
        let fmt = fmt::layer().compact();
        Registry::default()
            .with(EnvFilter::from_default_env())
            .with(fmt)
            .init()
    })
}
