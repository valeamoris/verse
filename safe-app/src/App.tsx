import { useEffect, useMemo, useState } from 'react'
import type SafeAppsSDK from '@safe-global/safe-apps-sdk'
import { encodeFunctionData, getAddress, isAddress, stringToHex, type Address, type Hex } from 'viem'
import { guardAbi, proxyAdminAbi, superchainConfigAbi, systemConfigAbi } from './abi'
import { execCalldata, fetchSafeTx, packSignatures, readGuardState, readTimelockDelay, rpcClient, scheduleCalldata, sendViaWallet } from './timelock'

type Props = { sdk: SafeAppsSDK }
type SafeInfo = { safeAddress: Address; chainId: number; threshold: number; owners: Address[] }
type SafeTx = { to: Address; value: string; data: Hex; operation?: 0 | 1 }

const empty = '0x0000000000000000000000000000000000000000' as Address
const configured = {
  proxyAdmin: import.meta.env.VITE_PROXY_ADMIN ?? '',
  systemConfig: import.meta.env.VITE_SYSTEM_CONFIG ?? '',
  guard: import.meta.env.VITE_TIMELOCK_GUARD ?? '',
  superchainConfig: import.meta.env.VITE_SUPERCHAIN_CONFIG ?? '',
  optimismPortal: import.meta.env.VITE_OPTIMISM_PORTAL ?? '',
  rpcUrl: import.meta.env.VITE_RPC_URL ?? 'https://ethereum-sepolia-rpc.publicnode.com',
}

function validAddress(value: string): value is Address { return isAddress(value) }

export function App({ sdk }: Props) {
  const [safe, setSafe] = useState<SafeInfo>()
  const [status, setStatus] = useState('Connecting to Safe Wallet...')
  const [proxyAdmin, setProxyAdmin] = useState(configured.proxyAdmin)
  const [systemConfig, setSystemConfig] = useState(configured.systemConfig)
  const [guard, setGuard] = useState(configured.guard)
  const [targetProxy, setTargetProxy] = useState('')
  const [implementation, setImplementation] = useState('')
  const [newAdmin, setNewAdmin] = useState('')
  const [systemAction, setSystemAction] = useState('setGasLimit')
  const [systemValue, setSystemValue] = useState('30000000')
  const [extraData, setExtraData] = useState('0x')
  const [lastTxHash, setLastTxHash] = useState(() => localStorage.getItem('verse-last-tx-hash') ?? '')
  const [lastData, setLastData] = useState<SafeTx>()
  const [busy, setBusy] = useState(false)
  const [tl, setTl] = useState<{ confirmations: number; state: number; executionTime: bigint; delay: bigint }>()
  const [tlError, setTlError] = useState('')
  const [manualTxHash, setManualTxHash] = useState('')
  const [now, setNow] = useState(() => Math.floor(Date.now() / 1000))
  const trackedTxHash = manualTxHash.trim() || lastTxHash
  const [scAddress, setScAddress] = useState(configured.superchainConfig)
  const [pauseIdentifier, setPauseIdentifier] = useState(configured.optimismPortal)
  const [pauseAction, setPauseAction] = useState<'pause' | 'unpause' | 'extend'>('pause')
  const [isPaused, setIsPaused] = useState<boolean>()

  useEffect(() => { sdk.safe.getInfo().then((info) => {
    setSafe({ safeAddress: getAddress(info.safeAddress), chainId: info.chainId, threshold: info.threshold, owners: info.owners.map(getAddress) })
    setStatus(`Connected · chain ${info.chainId}`)
  }).catch(() => setStatus('Open this page from a Safe Wallet Safe App context.')) }, [sdk])

  const client = useMemo(() => rpcClient(configured.rpcUrl), [])

  // Poll the Transaction Service + TimelockGuard for the latest proposal's
  // confirmation count, queue state and countdown.
  useEffect(() => {
    if (!safe || !trackedTxHash || !validAddress(guard)) return
    let alive = true
    const tick = async () => {
      try {
        const tx = await fetchSafeTx(safe.safeAddress, trackedTxHash)
        if (!tx) { if (alive) setTl(undefined); return }
        const [st, delaySecs] = await Promise.all([
          readGuardState(client, guard, safe.safeAddress, tx.safeTxHash),
          readTimelockDelay(client, guard, safe.safeAddress),
        ])
        if (!alive) return
        setTl({ confirmations: tx.confirmations.length, state: st.state, executionTime: st.executionTime, delay: delaySecs })
        setTlError('')
      } catch (e) {
        if (alive) setTlError(e instanceof Error ? e.message : String(e))
      }
    }
    tick()
    const poll = setInterval(tick, 10000)
    const clock = setInterval(() => setNow(Math.floor(Date.now() / 1000)), 1000)
    return () => { alive = false; clearInterval(poll); clearInterval(clock) }
  }, [safe, trackedTxHash, guard, client])

  const scheduleTx = async () => {
    if (!safe || !validAddress(guard) || !trackedTxHash) throw new Error('No proposal to schedule')
    const tx = await fetchSafeTx(safe.safeAddress, trackedTxHash)
    if (!tx) throw new Error('Transaction not found in the Transaction Service yet')
    if (tx.confirmations.length < safe.threshold) throw new Error(`Only ${tx.confirmations.length}/${safe.threshold} confirmations collected`)
    const data = scheduleCalldata(safe.safeAddress, tx, packSignatures(tx.confirmations))
    const hash = await sendViaWallet(client, guard, data, safe.chainId)
    setStatus(`Scheduled in guard queue · ${hash.slice(0, 12)}...`)
  }

  // Poll the SuperchainConfig paused flag for the selected identifier.
  useEffect(() => {
    if (!validAddress(scAddress) || !validAddress(pauseIdentifier)) { setIsPaused(undefined); return }
    let alive = true
    const tick = async () => {
      try {
        const paused = await client.readContract({
          address: getAddress(scAddress), abi: superchainConfigAbi, functionName: 'paused',
          args: [getAddress(pauseIdentifier)],
        })
        if (alive) setIsPaused(paused)
      } catch { if (alive) setIsPaused(undefined) }
    }
    tick()
    const poll = setInterval(tick, 15000)
    return () => { alive = false; clearInterval(poll) }
  }, [scAddress, pauseIdentifier, client])

  const pauseCall = () => {
    if (!validAddress(scAddress)) throw new Error('Enter a valid SuperchainConfig address')
    if (!validAddress(pauseIdentifier)) throw new Error('Enter a valid identifier (Portal address, or 0x0000…0 for global)')
    return submitSafeTx({ to: getAddress(scAddress), value: '0', data: encodeFunctionData({ abi: superchainConfigAbi, functionName: pauseAction as never, args: [getAddress(pauseIdentifier)] as never }) })
  }

  const executeTx = async () => {
    if (!safe || !validAddress(guard) || !trackedTxHash) throw new Error('No proposal to execute')
    const tx = await fetchSafeTx(safe.safeAddress, trackedTxHash)
    if (!tx) throw new Error('Transaction not found in the Transaction Service yet')
    const st = await readGuardState(client, guard, safe.safeAddress, tx.safeTxHash)
    if (st.state !== 1 || st.executionTime === 0n) throw new Error('Transaction is not scheduled in the guard queue')
    if (st.executionTime > BigInt(Math.floor(Date.now() / 1000))) throw new Error('Timelock delay has not passed yet')
    const data = execCalldata(tx, packSignatures(tx.confirmations))
    const hash = await sendViaWallet(client, safe.safeAddress, data, safe.chainId)
    setStatus(`Executed · ${hash.slice(0, 12)}...`)
  }

  const tlStateLabel = ['Not scheduled', 'Pending (queued)', 'Cancelled', 'Executed'][tl?.state ?? 0]

  const ready = !!safe && validAddress(proxyAdmin) && validAddress(systemConfig) && validAddress(guard)
  const submitSafeTx = async (tx: SafeTx) => {
    if (!safe) throw new Error('Safe context is not available')
    setBusy(true); setStatus('Submitting Safe transaction for owner signatures...')
    try {
      const response = await sdk.txs.send({ txs: [{ to: tx.to, value: tx.value, data: tx.data }] })
      setLastTxHash(response.safeTxHash ?? '')
      localStorage.setItem('verse-last-tx-hash', response.safeTxHash ?? '')
      setLastData(tx)
      setStatus(`Safe transaction proposed${response.safeTxHash ? ` · ${response.safeTxHash.slice(0, 10)}...` : ''}`)
    } finally { setBusy(false) }
  }

  const proxyCall = (name: 'upgrade' | 'upgradeAndCall' | 'changeProxyAdmin') => {
    if (!validAddress(proxyAdmin) || !validAddress(targetProxy)) throw new Error('Enter valid ProxyAdmin and proxy addresses')
    if (name !== 'changeProxyAdmin' && !validAddress(implementation)) throw new Error('Enter a valid implementation address')
    if (name === 'changeProxyAdmin' && !validAddress(newAdmin)) throw new Error('Enter a valid new admin address')
    const args = name === 'upgrade' ? [getAddress(targetProxy), getAddress(implementation)] as const : name === 'upgradeAndCall' ? [getAddress(targetProxy), getAddress(implementation), extraData as Hex] as const : [getAddress(targetProxy), getAddress(newAdmin)] as const
    return submitSafeTx({ to: getAddress(proxyAdmin), value: '0', data: encodeFunctionData({ abi: proxyAdminAbi, functionName: name, args }) })
  }

  const systemCall = () => {
    if (!validAddress(systemConfig)) throw new Error('Enter a valid SystemConfig address')
    // Build args for the selected action only: eager construction would run
    // getAddress()/BigInt() against values of the other (unselected) actions.
    let selected: { functionName: string; args: readonly unknown[] }
    const split = () => systemValue.split(',').map((v: string) => BigInt(v.trim()))
    switch (systemAction) {
      case 'setUnsafeBlockSigner':
        selected = { functionName: 'setUnsafeBlockSigner', args: [getAddress(systemValue)] }
        break
      case 'setBatcherHash':
        selected = { functionName: 'setBatcherHash', args: [systemValue as Hex] }
        break
      case 'setGasConfig':
        selected = { functionName: 'setGasConfig', args: split() }
        break
      case 'setGasConfigEcotone':
        selected = { functionName: 'setGasConfigEcotone', args: split() }
        break
      case 'setGasLimit':
        selected = { functionName: 'setGasLimit', args: [BigInt(systemValue)] }
        break
      case 'setEIP1559Params':
        selected = { functionName: 'setEIP1559Params', args: split() }
        break
      case 'setMinBaseFee':
        selected = { functionName: 'setMinBaseFee', args: [BigInt(systemValue)] }
        break
      case 'setOperatorFeeScalars':
        selected = { functionName: 'setOperatorFeeScalars', args: split() }
        break
      case 'setFeature': {
        // Arguments format: "FEATURE_NAME,true|false" (name may be a 0x-prefixed bytes32)
        const [name, flag] = systemValue.split(',').map((v: string) => v.trim())
        if (!name || (flag !== 'true' && flag !== 'false')) throw new Error('setFeature args: "FEATURE_NAME,true|false"')
        const feature = name.startsWith('0x') ? (name as Hex) : stringToHex(name, { size: 32 })
        selected = { functionName: 'setFeature', args: [feature, flag === 'true'] }
        break
      }
      case 'configureGasPayingTokenInPortal':
        selected = { functionName: 'configureGasPayingTokenInPortal', args: [] }
        break
      case 'transferOwnership':
        selected = { functionName: 'transferOwnership', args: [getAddress(systemValue)] }
        break
      default:
        throw new Error('Unsupported SystemConfig action')
    }
    return submitSafeTx({ to: getAddress(systemConfig), value: '0', data: encodeFunctionData({ abi: systemConfigAbi, functionName: selected.functionName as never, args: selected.args as never }) })
  }

  const run = (action: () => Promise<unknown>) => action().catch((error) => setStatus(error instanceof Error ? error.message : String(error)))

  return <main>
    <header><div><p className="eyebrow">VERSE GOVERNANCE</p><h1>Safe operations console</h1><p className="sub">ProxyAdmin and SystemConfig actions with Safe multisig review.</p></div><div className="connection"><span className={safe ? 'dot live' : 'dot'} />{status}</div></header>
    <section className="context panel"><div><span className="label">SAFE</span><strong>{safe?.safeAddress ?? 'Not connected'}</strong></div><div><span className="label">SIGNERS</span><strong>{safe ? `${safe.threshold} of ${safe.owners.length}` : '—'}</strong></div><div><span className="label">CHAIN</span><strong>{safe?.chainId ?? 'Sepolia'}</strong></div></section>
    <section className="panel config"><div className="section-title"><div><span className="eyebrow">01 / TARGETS</span><h2>Management contracts</h2></div><span className="hint">Addresses are validated before calldata is created.</span></div><div className="grid three"><Field label="ProxyAdmin" value={proxyAdmin} onChange={setProxyAdmin} /><Field label="SystemConfig proxy" value={systemConfig} onChange={setSystemConfig} /><Field label="TimelockGuard" value={guard} onChange={setGuard} /></div></section>
    <div className="columns">
      <section className="panel"><div className="section-title"><div><span className="eyebrow">02 / PROXY ADMIN</span><h2>Upgrade control</h2></div></div><Field label="Proxy address" value={targetProxy} onChange={setTargetProxy} /><Field label="New implementation" value={implementation} onChange={setImplementation} /><Field label="New proxy admin" value={newAdmin} onChange={setNewAdmin} /><Field label="Initializer calldata (optional)" value={extraData} onChange={setExtraData} /><div className="actions"><button disabled={!ready || busy} onClick={() => run(() => proxyCall('upgrade'))}>Propose upgrade</button><button disabled={!ready || busy} onClick={() => run(() => proxyCall('upgradeAndCall'))}>Propose upgrade + call</button><button className="secondary" disabled={!ready || busy} onClick={() => run(() => proxyCall('changeProxyAdmin'))}>Change admin</button></div></section>
      <section className="panel"><div className="section-title"><div><span className="eyebrow">03 / SYSTEM CONFIG</span><h2>Owner actions</h2></div><span className="hint">All setters are onlyOwner; setFeature / configureGasPayingTokenInPortal require ProxyAdmin owner rights.</span></div><label>Function<select value={systemAction} onChange={(e) => setSystemAction(e.target.value)}><option value="setGasLimit">setGasLimit(uint64)</option><option value="setUnsafeBlockSigner">setUnsafeBlockSigner(address)</option><option value="setBatcherHash">setBatcherHash(bytes32)</option><option value="setGasConfig">setGasConfig(uint256 overhead,uint256 scalar)</option><option value="setGasConfigEcotone">setGasConfigEcotone(uint32,uint32)</option><option value="setEIP1559Params">setEIP1559Params(uint32,uint32)</option><option value="setMinBaseFee">setMinBaseFee(uint64)</option><option value="setOperatorFeeScalars">setOperatorFeeScalars(uint32,uint64)</option><option value="setFeature">setFeature(bytes32,bool)</option><option value="configureGasPayingTokenInPortal">configureGasPayingTokenInPortal()</option><option value="transferOwnership">transferOwnership(address)</option></select></label><Field label="Arguments (comma separated where needed; setFeature: NAME,true|false)" value={systemValue} onChange={setSystemValue} /><div className="actions"><button disabled={!ready || busy} onClick={() => run(systemCall)}>Propose SystemConfig action</button></div></section>
    </div>
    <section className="panel timelock"><div className="section-title"><div><span className="eyebrow">04 / TIMELOCK</span><h2>Schedule &amp; execute</h2></div><span className="hint">Scheduling is sent from your browser wallet, not as a Safe self-call.</span></div><Field label="Safe tx hash (optional — paste a previously proposed hash)" value={manualTxHash} onChange={setManualTxHash} />{trackedTxHash ? <div className="result"><span>Tracked Safe transaction</span><code>{trackedTxHash}</code><span>Confirmations: {tl ? `${tl.confirmations}/${safe?.threshold ?? '—'}` : 'checking…'} · Guard delay: {tl ? `${tl.delay}s` : '—'} · Queue state: {tlStateLabel}</span>{!!tl && tl.state === 1 && tl.executionTime > 0n && <span>{BigInt(now) >= tl.executionTime ? <strong>READY — delay passed, execute now</strong> : `${Number(tl.executionTime) - now}s left (executes at ${new Date(Number(tl.executionTime) * 1000).toLocaleTimeString()})`}</span>}</div> : <div className="notice"><strong>Two-stage execution</strong><span>Propose an action above. Once threshold signatures are collected, click <strong>Schedule with wallet</strong> to queue the transaction in the TimelockGuard — your browser wallet pays gas. When the delay countdown finishes, click <strong>Execute</strong>.</span></div>}{tlError && <div className="notice"><strong>Timelock status</strong><span>{tlError}</span></div>}<div className="actions"><button disabled={!trackedTxHash || !safe || (tl?.confirmations ?? 0) < (safe?.threshold ?? 0) || (tl?.state ?? 0) !== 0} onClick={() => run(scheduleTx)}>Schedule with wallet (排队)</button><button className="secondary" disabled={!tl || tl.state !== 1 || tl.executionTime === 0n || BigInt(now) < tl.executionTime} onClick={() => run(executeTx)}>Execute (执行)</button></div></section>
    <section className="panel"><div className="section-title"><div><span className="eyebrow">05 / PORTAL PAUSE</span><h2>Emergency pause (guardian)</h2></div><span className="hint">Only the SuperchainConfig guardian may call these. Open this app from the Guardian Safe to act without timelock.</span></div><div className="grid two"><Field label="SuperchainConfig" value={scAddress} onChange={setScAddress} /><Field label="Identifier (Portal address; 0x0000…0 = global)" value={pauseIdentifier} onChange={setPauseIdentifier} /></div><div className="grid two"><label>Action<select value={pauseAction} onChange={(e) => setPauseAction(e.target.value as 'pause' | 'unpause' | 'extend')}><option value="pause">pause(address)</option><option value="unpause">unpause(address)</option><option value="extend">extend(address)</option></select></label><div className="notice"><strong>Paused status</strong><span>Identifier: {isPaused === undefined ? 'checking…' : isPaused ? '⛔ PAUSED' : '✅ not paused'}</span></div></div><div className="actions"><button className="danger" disabled={!safe || busy || !validAddress(scAddress) || !validAddress(pauseIdentifier)} onClick={() => run(pauseCall)}>Propose {pauseAction}</button></div></section>
    <footer><span>{ready ? 'Ready for Safe Wallet' : 'Configure contract addresses to continue'}</span><span>Guard address and transaction parameters must be verified before production use.</span></footer>
  </main>
}

function Field({ label, value, onChange }: { label: string; value: string; onChange: (value: string) => void }) { return <label>{label}<input value={value} onChange={(e) => onChange(e.target.value)} spellCheck={false} /></label> }
