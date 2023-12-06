//! Internal Utility functions for use in crate

#[cfg(test)]
use std::sync::Once;
#[cfg(test)]
use tracing_forest::ForestLayer;
#[cfg(test)]
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter, Registry};

#[cfg(test)]
static INIT: Once = Once::new();

#[cfg(test)]
pub(crate) fn init_logging() {
    INIT.call_once(|| {
        Registry::default()
            .with(ForestLayer::default())
            .with(EnvFilter::from_default_env())
            .init()
    })
}
