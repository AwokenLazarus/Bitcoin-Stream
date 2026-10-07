/**
 * The package's containers as plain data (AGP-040): which image, which user, which parts of the `main`
 * volume each one mounts, its environment and what it waits for. `main.ts` turns this into daemons, and
 * packaging/startos/test runs exactly these on Docker (the StartOS-shaped regtest run), so the test and the
 * package cannot drift. No SDK import here: `node --experimental-strip-types` loads it on its own.
 *
 * The `main` volume is laid out as docs/CONTAINER.md §1. StartOS mounts a volume root-owned on every start,
 * so the `init` oneshot (xbt-init, as root) gives each component's sub-dir to its uid first. Every daemon
 * then runs as its image's own non-root user and mounts only its sub-dir and the socket dirs it needs.
 */
export const PORTS = { ui: 8480, mcp: 33510, hub: 9480 } as const

export type ImageKey = 'init' | 'signer' | 'witness' | 'mcp' | 'ui' | 'hub'
export type DaemonId = 'init' | 'witness' | 'signer' | 'mcp' | 'ui' | 'hub'

export type MountSpec = { subpath: string | null; mountpoint: string; readonly: boolean }

export type ServiceSpec = {
  id: DaemonId
  image: ImageKey
  /** the image's own user unless set (only `init` runs as root) */
  user?: string
  command: [string, ...string[]]
  env: Record<string, string>
  mounts: MountSpec[]
  requires: DaemonId[]
  /** the port the service listens on (for readiness), if any */
  port?: number
  /** readiness: a command in the service's own image (the images have no shell) */
  readyCommand?: [string, ...string[]]
}

export type NodeConfig = {
  host: string
  port: number
  user: string
  password: string
  chain: 'main' | 'test' | 'regtest'
}

export type Config = {
  node: NodeConfig
  hubEnabled: boolean
  /** shown on the UI's Agents page: the MCP interface's addresses */
  mcpUrls: string[]
}

/** The local image tags (scripts/oci_build.sh --load); one image set for Umbrel, StartOS and xbt-compute. */
export const IMAGES: Record<ImageKey, string> = {
  init: 'xbt-init:0.1.0',
  signer: 'xbt-signer:0.1.0',
  witness: 'xbt-anchor-witness:0.1.0',
  mcp: 'xbt-wallet-mcp:0.1.0',
  ui: 'xbt-wallet-ui:0.1.0',
  hub: 'xbt402-hub:0.1.0',
}

const vol = (subpath: string | null, mountpoint: string, readonly = false): MountSpec => ({ subpath, mountpoint, readonly })

export function services(cfg: Config): ServiceSpec[] {
  const node = {
    XBT_NODE_RPC_HOST: cfg.node.host,
    XBT_NODE_RPC_PORT: String(cfg.node.port),
    XBT_CHAIN: cfg.node.chain,
  }
  const components = ['signer', 'witness', 'mcp', 'ui', ...(cfg.hubEnabled ? ['hub'] : [])]
  const out: ServiceSpec[] = [
    {
      id: 'init',
      image: 'init',
      user: 'root',
      command: ['/usr/bin/xbt-init', 'init'],
      env: {
        XBT_INIT_COMPONENTS: components.join(','),
        XBT_INIT_NODE_RPC_AUTH: `${cfg.node.user}:${cfg.node.password}`,
      },
      mounts: [vol(null, '/data')],
      requires: [],
    },
    {
      id: 'witness',
      image: 'witness',
      command: ['/usr/bin/xbt-anchor-witness', 'serve'],
      env: {},
      mounts: [vol('witness', '/data/witness'), vol('run/anchor', '/data/run/anchor')],
      requires: ['init'],
      readyCommand: ['/usr/bin/xbt-anchor-witness', 'healthcheck'],
    },
    {
      id: 'signer',
      image: 'signer',
      command: ['/usr/bin/xbt-signer'],
      env: { ...node },
      mounts: [vol('signer', '/data/signer'), vol('run/signer', '/data/run/signer'), vol('run/anchor', '/data/run/anchor', true)],
      requires: ['witness'],
      readyCommand: ['/usr/bin/xbt-signer', 'healthcheck'],
    },
    {
      id: 'mcp',
      image: 'mcp',
      command: ['/usr/bin/xbt-wallet-mcp'],
      // an over-threshold payment waits this long for the owner's approval in the UI
      env: { XBT_MCP_HTTP: `0.0.0.0:${PORTS.mcp}`, XBT_MCP_APPROVAL_WAIT_S: '300' },
      // the bearer token is the UI's run/ui/mcp-http-token (0640, group xbt-wallet-ui): read-only here (AGP-042)
      mounts: [vol('mcp', '/data/mcp'), vol('run/signer', '/data/run/signer', true), vol('run/ui', '/data/run/ui', true)],
      requires: ['signer'],
      port: PORTS.mcp,
    },
    {
      id: 'ui',
      image: 'ui',
      command: ['/usr/bin/xbt-wallet-ui', 'serve'],
      env: {
        XBT_UI_BIND: `0.0.0.0:${PORTS.ui}`,
        XBT_UI_SIGNER_SOCK: '/data/run/signer/signer.sock',
        XBT_UI_MCP_URL: cfg.mcpUrls.join(','),
        ...(cfg.hubEnabled ? { XBT_UI_HUB_URL: `http://127.0.0.1:${PORTS.hub}` } : {}),
      },
      // the UI owns the MCP token and rotates it on its Agents page (AGP-042)
      mounts: [vol('ui', '/data/ui'), vol('run/signer', '/data/run/signer', true), vol('run/ui', '/data/run/ui')],
      requires: ['signer'],
      port: PORTS.ui,
    },
  ]
  if (cfg.hubEnabled) {
    out.push({
      id: 'hub',
      image: 'hub',
      command: ['/usr/bin/xbt402-hub'],
      // the 402's resource.url follows the address the client used (LAN, .local, onion)
      env: { ...node, XBT_HUB_BIND: '0.0.0.0', XBT_HUB_PORT: String(PORTS.hub), XBT_TRUST_FORWARDED: '1' },
      mounts: [vol('hub', '/data/hub')],
      requires: ['init'],
      port: PORTS.hub,
    })
  }
  return out
}
