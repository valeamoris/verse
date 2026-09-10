import { createPublicClient, encodeFunctionData, http, type Address, type Hex } from 'viem'
import { sepolia } from 'viem/chains'

// Transaction Service endpoints (fallback list; the gateway may redirect between hosts).
const TX_SERVICES = [
  'https://safe-transaction-sepolia.safe.global/api/v1',
  'https://safe-client.safe.global/v1/chains/11155111',
]

export const guardScheduleAbi = [
  { type: 'function', name: 'scheduleTransaction', stateMutability: 'nonpayable', inputs: [
    { name: '_safe', type: 'address' }, { name: '_nonce', type: 'uint256' },
    { name: '_params', type: 'tuple', components: [
      { name: 'to', type: 'address' }, { name: 'value', type: 'uint256' }, { name: 'data', type: 'bytes' },
      { name: 'operation', type: 'uint8' }, { name: 'safeTxGas', type: 'uint256' }, { name: 'baseGas', type: 'uint256' },
      { name: 'gasPrice', type: 'uint256' }, { name: 'gasToken', type: 'address' }, { name: 'refundReceiver', type: 'address' }] },
    { name: '_signatures', type: 'bytes' }], outputs: [] },
  { type: 'function', name: 'scheduledTransaction', stateMutability: 'view', inputs: [
    { name: '_safe', type: 'address' }, { name: '_txHash', type: 'bytes32' }], outputs: [
    { type: 'tuple', components: [
      { name: 'executionTime', type: 'uint256' }, { name: 'state', type: 'uint8' },
      { name: 'params', type: 'tuple', components: [
        { name: 'to', type: 'address' }, { name: 'value', type: 'uint256' }, { name: 'data', type: 'bytes' },
        { name: 'operation', type: 'uint8' }, { name: 'safeTxGas', type: 'uint256' }, { name: 'baseGas', type: 'uint256' },
        { name: 'gasPrice', type: 'uint256' }, { name: 'gasToken', type: 'address' }, { name: 'refundReceiver', type: 'address' }] }] }] },
  { type: 'function', name: 'timelockConfiguration', stateMutability: 'view', inputs: [{ name: '_safe', type: 'address' }], outputs: [{ name: 'timelockDelay', type: 'uint256' }] },
] as const

export const safeExecAbi = [
  { type: 'function', name: 'execTransaction', stateMutability: 'payable', inputs: [
    { name: 'to', type: 'address' }, { name: 'value', type: 'uint256' }, { name: 'data', type: 'bytes' },
    { name: 'operation', type: 'uint8' }, { name: 'safeTxGas', type: 'uint256' }, { name: 'baseGas', type: 'uint256' },
    { name: 'gasPrice', type: 'uint256' }, { name: 'gasToken', type: 'address' },
    { name: 'refundReceiver', type: 'address' }, { name: 'signatures', type: 'bytes' }], outputs: [{ name: 'success', type: 'bool' }] },
] as const

export type Confirmation = { owner: string; signature: string }
export type SafeTxRecord = {
  to: string
  value: string
  data: string
  operation: number
  safeTxGas: string
  baseGas: string
  gasPrice: string
  gasToken: string
  refundReceiver: string
  nonce: number
  safeTxHash: string
  confirmations: Confirmation[]
}

export type GuardState = { executionTime: bigint; state: number }

export function rpcClient(rpcUrl: string) {
  return createPublicClient({ chain: sepolia, transport: http(rpcUrl) })
}

export async function fetchSafeTx(safeAddress: string, safeTxHash: string): Promise<SafeTxRecord | null> {
  let lastErr: unknown
  for (const base of TX_SERVICES) {
    try {
      const res = await fetch(`${base}/safes/${safeAddress}/multisig-transactions/?safe_tx_hash=${safeTxHash}&limit=1`, { redirect: 'follow' })
      if (!res.ok) { lastErr = new Error(`GET -> ${res.status}`); continue }
      const json = await res.json()
      const t = (json.results ?? [])[0]
      if (!t) return null
      return {
        to: t.to, value: t.value, data: t.data ?? '0x', operation: t.operation,
        safeTxGas: t.safeTxGas, baseGas: t.baseGas, gasPrice: t.gasPrice,
        gasToken: t.gasToken, refundReceiver: t.refundReceiver, nonce: t.nonce,
        safeTxHash: t.safeTxHash, confirmations: (t.confirmations ?? []) as Confirmation[],
      }
    } catch (e) { lastErr = e }
  }
  throw lastErr instanceof Error ? lastErr : new Error('Transaction Service unreachable')
}

/// Pack EOA signatures sorted by owner address (ascending), as Safe expects.
export function packSignatures(confirmations: Confirmation[]): Hex {
  const sorted = [...confirmations].sort((a, b) => (a.owner.toLowerCase() < b.owner.toLowerCase() ? -1 : 1))
  return `0x${sorted.map((c) => c.signature.slice(2)).join('')}` as Hex
}

export function scheduleCalldata(safe: string, tx: SafeTxRecord, signatures: Hex): Hex {
  const params = {
    to: tx.to as Address, value: BigInt(tx.value), data: tx.data as Hex, operation: tx.operation as 0 | 1,
    safeTxGas: BigInt(tx.safeTxGas), baseGas: BigInt(tx.baseGas), gasPrice: BigInt(tx.gasPrice),
    gasToken: tx.gasToken as Address, refundReceiver: tx.refundReceiver as Address,
  }
  return encodeFunctionData({
    abi: guardScheduleAbi, functionName: 'scheduleTransaction',
    args: [safe as Address, BigInt(tx.nonce), params, signatures],
  })
}

export function execCalldata(tx: SafeTxRecord, signatures: Hex): Hex {
  return encodeFunctionData({
    abi: safeExecAbi, functionName: 'execTransaction',
    args: [
      tx.to as Address, BigInt(tx.value), tx.data as Hex, tx.operation as 0 | 1,
      BigInt(tx.safeTxGas), BigInt(tx.baseGas), BigInt(tx.gasPrice),
      tx.gasToken as Address, tx.refundReceiver as Address, signatures,
    ],
  })
}

export async function readGuardState(client: ReturnType<typeof rpcClient>, guard: string, safe: string, txHash: string): Promise<GuardState> {
  const result = await client.readContract({
    address: guard as Address, abi: guardScheduleAbi, functionName: 'scheduledTransaction',
    args: [safe as Address, txHash as Hex],
  })
  // viem may decode the tuple as an array; normalize.
  const st = Array.isArray(result) ? { executionTime: result[0] as bigint, state: result[1] as number } : result
  return { executionTime: st.executionTime, state: st.state }
}

export async function readTimelockDelay(client: ReturnType<typeof rpcClient>, guard: string, safe: string): Promise<bigint> {
  return await client.readContract({
    address: guard as Address, abi: guardScheduleAbi, functionName: 'timelockConfiguration',
    args: [safe as Address],
  })
}

/// Simulate the call first, then hand it to the user's browser wallet (EOA pays gas).
export async function sendViaWallet(client: ReturnType<typeof rpcClient>, to: string, data: Hex, chainId: number): Promise<string> {
  const win = window as unknown as { ethereum?: { request: (args: unknown) => Promise<unknown> } }
  if (!win.ethereum) throw new Error('No browser wallet found. Install MetaMask (or similar) and reload.')
  const accounts = (await win.ethereum.request({ method: 'eth_requestAccounts' })) as string[]
  const from = accounts[0]
  // Make sure the wallet is on the Safe's chain before sending.
  try {
    await win.ethereum.request({ method: 'wallet_switchEthereumChain', params: [{ chainId: `0x${chainId.toString(16)}` }] })
  } catch {
    throw new Error(`Please switch your wallet to chain ${chainId}`)
  }
  // Dry-run first: the wallet prompt only appears if the call would succeed.
  await client.call({ account: from as Address, to: to as Address, data })
  const txHash = await win.ethereum.request({
    method: 'eth_sendTransaction',
    params: [{ from, to, data }],
  })
  return String(txHash)
}
