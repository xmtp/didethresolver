//! Internal Utility functions for use in crate

#[cfg(test)]
use std::sync::Once;
use tracing_forest::ForestLayer;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter, Registry};

#[cfg(test)]
static INIT: Once = Once::new();

pub(crate) fn init_logging() {
    Registry::default()
        .with(ForestLayer::default())
        .with(EnvFilter::from_default_env())
        .init()
}

#[cfg(test)]
#[ctor::ctor]
fn __init_test_logging() {
    INIT.call_once(|| {
        Registry::default()
            .with(ForestLayer::default())
            .with(EnvFilter::from_default_env())
            .init()
    })
}
