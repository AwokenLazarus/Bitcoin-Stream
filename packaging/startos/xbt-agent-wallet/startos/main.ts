import { i18n } from './i18n'
import { sdk } from './sdk'
import { storeJson } from './fileModels/store.json'
import { PORTS, services, ServiceSpec } from './spec'

export const main = sdk.setupMain(async ({ effects }) => {
  const store = await storeJson.read().const(effects)
  if (!store) throw new Error('store.json is missing')

  // the MCP interface's addresses, for the UI's Agents page (main re-runs when they change)
  const mcpHost = await sdk.host.getOwn(effects, 'mcp').const()
  const mcpIface = Object.values(mcpHost?.bindings ?? {})
    .flatMap((b) => Object.values(b.interfaces))
    .find((i) => i.id === 'mcp')
  const mcpUrls = (mcpIface?.addressInfo?.nonLocal.format('urlstring') ?? []).map((u) => u.replace(/\/$/, '') + '/mcp')

  const specs = services({ node: store.node, hubEnabled: store.hubEnabled, mcpUrls })
  const spec = (id: ServiceSpec['id']) => specs.find((s) => s.id === id) as ServiceSpec

  const sub = (s: ServiceSpec) => {
    let mounts = sdk.Mounts.of()
    for (const m of s.mounts) {
      mounts = mounts.mountVolume({ volumeId: 'main', subpath: m.subpath, mountpoint: m.mountpoint, readonly: m.readonly })
    }
    return sdk.SubContainer.of(effects, { imageId: s.image }, mounts, `${s.id}-sub`)
  }
  const exec = (s: ServiceSpec) => ({ command: s.command, env: s.env, ...(s.user ? { user: s.user } : {}) })
  const portReady = (s: ServiceSpec) => () =>
    sdk.healthCheck.checkPortListening(effects, s.port as number, {
      successMessage: i18n('Listening'),
      errorMessage: i18n('Not listening yet'),
    })
  const scriptReady = (s: ServiceSpec, subc: ReturnType<typeof sub>) => () =>
    sdk.healthCheck.runHealthScript(s.readyCommand as [string, ...string[]], subc, { errorMessage: i18n('Not ready yet') })

  const [init, witness, signer, mcp, ui] = (['init', 'witness', 'signer', 'mcp', 'ui'] as const).map(spec)
  const witnessSub = sub(witness)
  const signerSub = sub(signer)

  // init first (xbt-init: owners and modes on the root-owned volume, the node credentials, the MCP token),
  // then the witness, the signer, and the two services on the signer's socket
  const daemons = sdk.Daemons.of(effects)
    .addOneshot('init', { subcontainer: sub(init), exec: exec(init), requires: [] })
    .addDaemon('witness', {
      subcontainer: witnessSub,
      exec: exec(witness),
      ready: { display: null, fn: scriptReady(witness, witnessSub), gracePeriod: 30_000 },
      requires: ['init'],
    })
    .addDaemon('signer', {
      subcontainer: signerSub,
      exec: exec(signer),
      ready: { display: null, fn: scriptReady(signer, signerSub), gracePeriod: 60_000 },
      requires: ['witness'],
    })
    .addDaemon('mcp', {
      subcontainer: sub(mcp),
      exec: exec(mcp),
      ready: { display: i18n('MCP server for agents'), fn: portReady(mcp), gracePeriod: 30_000 },
      requires: ['signer'],
    })
    .addDaemon('ui', {
      subcontainer: sub(ui),
      exec: exec(ui),
      ready: { display: i18n('Web interface'), fn: portReady(ui), gracePeriod: 30_000 },
      requires: ['signer'],
    })
    // Readiness as the wallet sees it: the MCP's /readyz (the signer is up, the node is reachable and synced,
    // the keys are unlocked, the witness answers). A 503 while the node syncs is "loading", with the reason.
    .addHealthCheck('wallet-ready', {
      ready: {
        display: i18n('Wallet ready to pay'),
        fn: async () => {
          try {
            const r = await fetch(`http://127.0.0.1:${PORTS.mcp}/readyz`)
            if (r.status === 200) return { result: 'success', message: i18n('Ready: the node is synced and the keys are unlocked') }
            const body = (await r.json().catch(() => ({}))) as {
              signer_ready?: { node?: { reachable?: boolean; synced?: boolean }; witness?: { reachable?: boolean } }
            }
            const sr = body.signer_ready ?? {}
            const why = !sr.node?.reachable
              ? i18n('The XBT node is not reachable: check the Node connection action')
              : !sr.node?.synced
                ? i18n('The XBT node is syncing')
                : sr.witness?.reachable === false
                  ? i18n('The anchor witness is not answering')
                  : i18n('The signer is starting')
            return { result: 'loading', message: why }
          } catch {
            return { result: 'starting', message: i18n('The MCP server is starting') }
          }
        },
      },
      requires: ['mcp'],
    })

  if (!store.hubEnabled) return daemons
  const hub = spec('hub')
  return daemons.addDaemon('hub', {
    subcontainer: sub(hub),
    exec: exec(hub),
    ready: { display: i18n('xbt402 hub'), fn: portReady(hub), gracePeriod: 30_000 },
    requires: ['init'],
  })
})
