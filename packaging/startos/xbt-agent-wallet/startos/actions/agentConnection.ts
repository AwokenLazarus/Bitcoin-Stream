import { i18n } from '../i18n'
import { sdk } from '../sdk'

/** What an agent needs: the MCP endpoint (this service's MCP interface) and the bearer token (xbt-init makes it once). */
export const agentConnection = sdk.Action.withoutInput(
  'agent-connection',
  {
    name: i18n('Agent connection'),
    description: i18n('The MCP endpoint and bearer token your AI agents use to pay through this wallet'),
    warning: i18n('Anyone with the token can pay what your policy allows. Give it only to your agents.'),
    allowedStatuses: 'any',
    group: null,
    visibility: 'enabled',
  },
  async ({ effects }) => {
    const token = String(await sdk.volumes.main.readFile('run/ui/mcp-http-token', 'utf8').catch(() => '')).trim()
    const host = await sdk.host.getOwn(effects, 'mcp').once()
    const iface = Object.values(host?.bindings ?? {})
      .flatMap((b) => Object.values(b.interfaces))
      .find((i) => i.id === 'mcp')
    const urls = (iface?.addressInfo?.nonLocal.format('urlstring') ?? []).map((u) => u.replace(/\/$/, '') + '/mcp')
    if (!token) {
      return { version: '1', title: i18n('Agent connection'), message: i18n('Start the service once to create the token.'), result: null }
    }
    return {
      version: '1',
      title: i18n('Agent connection'),
      message: i18n('Configure your agent with an MCP server over HTTP at one of these addresses and this bearer token.'),
      result: {
        type: 'group',
        value: [
          ...urls.map((u) => ({
            type: 'single' as const,
            name: i18n('MCP endpoint'),
            description: null,
            value: u,
            masked: false,
            copyable: true,
            qr: false,
          })),
          { type: 'single', name: i18n('Bearer token'), description: null, value: token, masked: true, copyable: true, qr: false },
        ],
      },
    }
  },
)
