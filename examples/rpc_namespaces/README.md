# RPC Composition Example

Example of composing a did:ethr resolution server with multiple other
namespaces/rpcs.

This example creates a did:ethr resolver connected to the Sepolia Ethereum
testnet and composes the rpc with the "TurtleMethods" rpc.

All did methods will be available under the `did_` namespace, all turtle methods
under the `turtle_` namespace.

Try running this example and executing the command

```bash
curl -H "Content-Type: application/json" -d '{"id":1, "jsonrpc":"2.0", "method": "rpc_methods"}' http://localhost:9999/ | jq .result`
```

(requires `curl` and `jq` packages to be installed)
