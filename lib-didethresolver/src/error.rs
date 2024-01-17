use ethers::{contract::ContractError, providers::Middleware};
use jsonrpsee::types::ErrorObjectOwned;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ResolverError<M: Middleware> {
    #[error(transparent)]
    Builder(#[from] EthrBuilderError),
    #[error(transparent)]
    ContractError(#[from] ContractError<M>),
    #[error("{0}")]
    Middleware(String),
}

#[derive(Error, Debug)]
pub enum DidError {
    #[error("Parsing of ethr:did failed, {0}")]
    Parse(#[from] peg::error::ParseError<peg::str::LineCol>),
    #[error(transparent)]
    Url(#[from] url::ParseError),
}

#[derive(Error, Debug)]
pub enum EthrBuilderError {
    #[error(transparent)]
    Did(#[from] DidError),
    #[error("Parsing of an endpoint or url failed {0}")]
    Url(#[from] url::ParseError),
    #[error(transparent)]
    Hex(#[from] hex::FromHexError),
}

impl<M: Middleware> From<ResolverError<M>> for ErrorObjectOwned {
    fn from(err: ResolverError<M>) -> Self {
        ErrorObjectOwned::owned(-31000, err.to_string(), None::<()>)
    }
}
/*
impl<M: Middleware> std::fmt::Display for ResolverError<M> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ResolverError::Builder(e) => write!(f, "{}", e),
            ResolverError::ContractError(e) => match e {
                //TODO: Can flesh out each error type here, checking if it's a serde provider or
                //inner error: [doc](https://docs.rs/ethers/2.0.11/ethers/middleware/trait.MiddlewareError.html)
                ContractError::MiddlewareError { .. } => write!(f, "{}", "Middleware Error"),
                e => write!(f, "{}", e),
            },
            ResolverError::Middleware(e) => write!(f, "{}", e),
        }
    }
}
*/

pub fn into_error<M: Middleware>(err: ResolverError<M>) -> ResolverError<M> {
    ResolverError::Middleware(err.to_string())
}
