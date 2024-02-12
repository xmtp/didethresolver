# Test Transactions

# NOTE: NOT MEANT FOR PRODUCTION USE. USE AT YOUR OWN RISK.

Small binary to send a test `set_attribute` transaction to EVM-based chains

Arguments:

- `network`: The network RPC-URL to interact with (Default: Sepolia)
- `contract`: The Address of the DID Registry contract to interact with
  (default: Test deployment on Sepolia)
- `wallet`: Path to a local JSON wallet. Ensure usage of a test wallet, the
  security of this binary has not been verified. Use at your own risk. (default:
  `./wallet.json`)
