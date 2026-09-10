# Verse Safe App

This is a Safe App prototype for Sepolia governance operations. It uses the Safe App SDK to create Safe transaction proposals and viem to encode a constrained set of `ProxyAdmin` and `SystemConfig` calls.

## Run

```powershell
cd safe-app
npm install
npm run dev
```

The app can be opened directly in Safe Wallet as a custom Safe App URL. Optional Vite variables are `VITE_PROXY_ADMIN`, `VITE_SYSTEM_CONFIG`, `VITE_TIMELOCK_GUARD`, and `VITE_RPC_URL`.

## Timelock flow

`Safe.txs.send` only proposes the underlying Safe transaction. The app deliberately does not submit `scheduleTransaction` as a Safe self-call: doing so would be blocked by the guard's `checkTransaction` hook. A relayer endpoint should be added next to read Safe Transaction Service confirmations, pack the signatures, submit `scheduleTransaction`, and execute the original Safe transaction after `executionTime`.

Before production use, add Safe Transaction Service confirmation retrieval, signature packing, nonce lookup, transaction simulation, and a relayer with replay protection.
