mod integration_util;

// use didethresolver::rpc::DidRegistryServer;

pub const SEPOLIA_URL: &str = "...";
pub const CONTRACT_URL: &str = "...";

#[test]
#[should_panic]
pub fn test_resolve_did() {
    crate::integration_util::init_logging();
    todo!()
    // stub
}
