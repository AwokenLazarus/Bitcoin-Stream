import { i18n } from './i18n'
import { sdk } from './sdk'
import { storeJson } from './fileModels/store.json'
import { PORTS } from './spec'

/**
 * The web UI (for the owner), the MCP server (for agents: an API with a bearer token) and, when enabled, the
 * xbt402 hub (a paid public API). StartOS offers each on the LAN; the owner can add a Tor address to any of
 * them from the service's Interfaces tab.
 */
export const setInterfaces = sdk.setupInterfaces(async ({ effects }) => {
  const receipts = []

  const ui = await sdk.MultiHost.of(effects, 'ui').bindPort(PORTS.ui, { protocol: 'http', preferredExternalPort: 80 })
  receipts.push(
    await ui.export([
      sdk.createInterface(effects, {
        name: i18n('Web interface'),
        id: 'ui',
        description: i18n('Set the policy, approve payments, and see balances, channels and the signature log'),
        type: 'ui',
        masked: false,
        schemeOverride: null,
        username: null,
        path: '',
        query: {},
      }),
    ]),
  )

  const mcp = await sdk.MultiHost.of(effects, 'mcp').bindPort(PORTS.mcp, { protocol: 'http', preferredExternalPort: PORTS.mcp })
  receipts.push(
    await mcp.export([
      sdk.createInterface(effects, {
        name: i18n('MCP server for agents'),
        id: 'mcp',
        description: i18n('Agents connect here (path /mcp) with the bearer token from the Agent connection action'),
        type: 'api',
        masked: true,
        schemeOverride: null,
        username: null,
        path: '/mcp',
        query: {},
      }),
    ]),
  )

  const hubEnabled = await storeJson.read((s) => s.hubEnabled).const(effects)
  if (hubEnabled) {
    const hub = await sdk.MultiHost.of(effects, 'hub').bindPort(PORTS.hub, { protocol: 'http', preferredExternalPort: PORTS.hub })
    receipts.push(
      await hub.export([
        sdk.createInterface(effects, {
          name: i18n('xbt402 hub'),
          id: 'hub',
          description: i18n('The paid xbt402 routing hub other wallets pay through'),
          type: 'api',
          masked: false,
          schemeOverride: null,
          username: null,
          path: '',
          query: {},
        }),
      ]),
    )
  }
  return receipts
})
