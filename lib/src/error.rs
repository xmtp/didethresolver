use ethers::{
    abi::EncodePackedError,
    contract::ContractError,
    providers::{Middleware, ProviderError},
    signers::WalletError,
};
use jsonrpsee::types::ErrorObjectOwned;
use thiserror::Error;

/// Errors originating from resolution with the [`Resolver`](crate::resolver::Resolver)
#[derive(Error, Debug)]
pub enum ResolverError<M: Middleware> {
    #[error(transparent)]
    Builder(#[from] EthrBuilderError),
    #[error(transparent)]
    ContractError(#[from] ContractError<M>),
    #[error("{0}")]
    Middleware(String),
}

/// Errors originating from the parsing of a did url identifier, [`Did`](crate::types::DidUrl)
#[derive(Error, Debug, PartialEq)]
pub enum DidError {
    #[error("Parsing of ethr:did failed, {0}")]
    Parse(#[from] peg::error::ParseError<peg::str::LineCol>),
    #[error(transparent)]
    Url(#[from] url::ParseError),
}

/// Errors originating during the construction of a ethr:did document [`EthrBuilder`](crate::types::EthrBuilder)
#[derive(Error, Debug, PartialEq)]
pub enum EthrBuilderError {
    #[error(transparent)]
    Did(#[from] DidError),
    #[error("Parsing of an endpoint or url failed {0}")]
    Url(#[from] url::ParseError),
    #[error(transparent)]
    Hex(#[from] hex::FromHexError),
    #[error("Parsing part of ethr:did failed, {0}")]
    Parse(#[from] peg::error::ParseError<peg::str::LineCol>),
    #[error("XMTP Key is missing key purpose metadata")]
    MissingMetadata,
}

impl<M: Middleware> From<ResolverError<M>> for ErrorObjectOwned {
    fn from(err: ResolverError<M>) -> Self {
        ErrorObjectOwned::owned(-31000, err.to_string(), None::<()>)
    }
}

#[derive(Error, Debug)]
pub enum RegistrySignerError<M: Middleware> {
    #[error(transparent)]
    Encode(#[from] EncodePackedError),
    #[error("{0}")]
    ContractError(#[from] ContractError<M>),
    #[error(transparent)]
    Provider(#[from] ProviderError),
    #[error(transparent)]
    Wallet(#[from] WalletError),
}

/// General type error
#[derive(Error, Debug)]
pub enum TypeError {
    #[error(transparent)]
    HexConversion(#[from] hex::FromHexError),
    #[error(transparent)]
    Base58Conversion(#[from] bs58::decode::Error),
    #[error(transparent)]
    Base64Conversion(#[from] base64::DecodeError),
}
