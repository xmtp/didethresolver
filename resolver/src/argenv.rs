use clap::Parser;

//
// system arguments and environment for the service
//

/// The address vanity of the DID Registry contract
pub const DID_ETH_REGISTRY: &str = "0xd1D374DDE031075157fDb64536eF5cC13Ae75000";

pub(crate) const DEFAULT_HOST: &str = "127.0.0.1";
pub(crate) const DEFAULT_PORT: u16 = 0;
pub(crate) const DEFAULT_RPC_URL: &str = "wss://127.0.0.1:8545";

#[derive(Parser, Debug)]
#[command(
    name = "didethresolver",
    version = "0.1.0",
    about = "Ethereum DID Resolver"
)]
pub struct Args {
    #[arg(short = 'p', long = "port", env = "RESOLVER_PORT", default_value_t = DEFAULT_PORT)]
    pub port: u16,
    #[arg(short = 's', long = "host", env = "RESOLVER_HOST", default_value = DEFAULT_HOST)]
    pub host: String,
    #[arg(short = 'r', long = "rpc-url", env = "RPC_URL", default_value = DEFAULT_RPC_URL)]
    pub rpc_url: String,
    #[arg(short = 'd', long = "did-registry", env = "DID_REGISTRY", default_value = DID_ETH_REGISTRY)]
    pub did_registry: String,
}

pub fn parse_args() -> Args {
    let args = Args::parse();
    log::info!("Args: {:?}", args);
    args
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;

    #[test]
    fn test_parse_args() -> anyhow::Result<()> {
        let env = setup();
        let args = parse_args();
        assert_eq!(args.host, DEFAULT_HOST);
        assert_eq!(args.port, DEFAULT_PORT);
        assert_eq!(args.rpc_url, DEFAULT_RPC_URL);
        assert_eq!(args.did_registry, DID_ETH_REGISTRY);
        putback(env)
    }

    #[test]
    fn test_parse_host_arg() -> anyhow::Result<()> {
        let env = setup();
        let args = Args::parse_from(["didethresolver", "-s", "host.xyz"]);
        assert_eq!(args.host, "host.xyz");
        assert_eq!(args.port, DEFAULT_PORT);
        assert_eq!(args.rpc_url, DEFAULT_RPC_URL);
        assert_eq!(args.did_registry, DID_ETH_REGISTRY);
        let args2 = Args::parse_from(["didethresolver", "--host", "h.xyz"]);
        assert_eq!(args2.host, "h.xyz");
        putback(env)
    }

    #[test]
    fn test_parse_port_arg() -> anyhow::Result<()> {
        let env = setup();
        let args = Args::parse_from(["didethresolver", "-p", "1234"]);
        assert_eq!(args.host, DEFAULT_HOST);
        assert_eq!(args.port, 1234);
        assert_eq!(args.rpc_url, DEFAULT_RPC_URL);
        assert_eq!(args.did_registry, DID_ETH_REGISTRY);
        let args2 = Args::parse_from(["didethresolver", "--port", "4321"]);
        assert_eq!(args2.host, DEFAULT_HOST);
        assert_eq!(args2.port, 4321);
        putback(env)
    }

    #[test]
    fn test_parse_rpc_url_arg() -> anyhow::Result<()> {
        let env = setup();
        let args = Args::parse_from(["didethresolver", "-r", "http://rpc.xyz"]);
        assert_eq!(args.host, DEFAULT_HOST);
        assert_eq!(args.port, DEFAULT_PORT);
        assert_eq!(args.rpc_url, "http://rpc.xyz");
        assert_eq!(args.did_registry, DID_ETH_REGISTRY);
        let args2 = Args::parse_from(["didethresolver", "--rpc-url", "http://rpc2.xyz"]);
        assert_eq!(args2.host, DEFAULT_HOST);
        assert_eq!(args2.port, DEFAULT_PORT);
        assert_eq!(args2.rpc_url, "http://rpc2.xyz");
        putback(env)
    }

    #[test]
    fn test_parse_did_registry_arg() -> anyhow::Result<()> {
        let env = setup();
        let args = Args::parse_from(["didethresolver", "-d", "0x1234567890"]);
        assert_eq!(args.host, DEFAULT_HOST);
        assert_eq!(args.port, DEFAULT_PORT);
        assert_eq!(args.rpc_url, DEFAULT_RPC_URL);
        assert_eq!(args.did_registry, "0x1234567890");
        let args2 = Args::parse_from([
            "didethresolver",
            "--did-registry",
            "0x0987654321",
            "--rpc-url",
            "http://rpc2.xyz",
        ]);
        assert_eq!(args2.host, DEFAULT_HOST);
        assert_eq!(args2.port, DEFAULT_PORT);
        assert_eq!(args2.rpc_url, "http://rpc2.xyz");
        assert_eq!(args2.did_registry, "0x0987654321");
        putback(env)
    }

    fn setup() -> Vec<(String, String)> {
        let env = std::env::vars().collect::<Vec<(String, String)>>();
        env::remove_var("RESOLVER_HOST");
        env::remove_var("RESOLVER_PORT");
        env::remove_var("RPC_URL");
        env::remove_var("DID_REGISTRY");
        env
    }

    fn putback(env: Vec<(String, String)>) -> anyhow::Result<()> {
        env::remove_var("RESOLVER_HOST");
        env::remove_var("RESOLVER_PORT");
        env::remove_var("RPC_URL");
        env::remove_var("DID_REGISTRY");
        for e in env {
            env::set_var(e.0, e.1);
        }
        Ok(())
    }
}
