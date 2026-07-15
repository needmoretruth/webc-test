# WEBC devnet reference demo

A tiny static page that drives the full WEBC devnet flow against a local
`webc-node` from the browser: create a wallet, request faucet funds, read the
account and its Merkle proof, submit a signed transfer, and watch finality live
over a WebSocket.

Everything here is **devnet only** — the WEBC units carry no real-world value.

## Run it

1. Build the SDK (produces `../dist/index.js`, which the page imports):

   ```bash
   cd sdk/webc-js
   pnpm install
   pnpm build
   ```

2. Start a devnet node (durable redb store, auto-sealing every 2s, faucet on):

   ```bash
   cargo run -p webc-node -- run --listen 127.0.0.1:8645
   ```

   The node serves the versioned API at `http://127.0.0.1:8645/v1` and enables a
   permissive CORS policy so a browser page from any origin can call it (devnet
   only).

3. Serve this SDK folder statically and open the demo, for example:

   ```bash
   cd sdk/webc-js
   python3 -m http.server 8080
   # then open http://127.0.0.1:8080/demo/
   ```

4. Click through: **Connect → Create wallet → Request faucet → Refresh account →
   Send 1 WEBC**. The status line updates its height live as blocks seal.

## What it demonstrates

- `WebcNodeClient` (HTTP + WebSocket) talking to the node `/v1` API.
- `createWallet` + `signTransaction` producing a transfer whose canonical signing
  bytes match the Rust node exactly (the node accepts and executes it).
- The devnet faucet funding a brand-new wallet to finality.
- Live block subscription over WebSocket.

The same flow is exercised headlessly by the SDK's tests and was verified
end-to-end against a running node.
