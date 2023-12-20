//! Internal Utility functions for use in crate

#[cfg(test)]
use std::sync::Once;
use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter, Registry};

#[cfg(test)]
static INIT: Once = Once::new();

pub(crate) fn init_logging() {
    let fmt = fmt::layer().compact();
    Registry::default()
        .with(EnvFilter::from_default_env())
        .with(fmt)
        .init()
}

#[cfg(test)]
#[ctor::ctor]
fn __init_test_logging() {
    INIT.call_once(|| {
        let fmt = fmt::layer().compact();
        Registry::default()
            .with(EnvFilter::from_default_env())
            .with(fmt)
            .init()
    })
}
