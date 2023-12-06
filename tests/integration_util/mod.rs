//! Shared setup code for integration tests
use std::sync::Once;
use tracing_forest::ForestLayer;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter, Registry};

static INIT: Once = Once::new();

pub(crate) fn init_logging() {
    INIT.call_once(|| {
        Registry::default()
            .with(ForestLayer::default())
            .with(EnvFilter::from_default_env())
            .init()
    })
}
