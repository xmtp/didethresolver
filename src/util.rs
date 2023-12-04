#[cfg(test)]
use std::sync::Once;
use tracing_forest::ForestLayer;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter, Registry};

#[cfg(not(test))]
pub fn init_logging() {
    Registry::default()
        .with(ForestLayer::default())
        .with(EnvFilter::from_default_env())
        .init();
}

#[cfg(test)]
static INIT: Once = Once::new();

#[cfg(test)]
pub fn init_logging() {
    INIT.call_once(|| {
        Registry::default()
            .with(ForestLayer::default())
            .with(EnvFilter::from_default_env())
            .init()
    })
}
