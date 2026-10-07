import { i18n } from '../i18n'
import { sdk } from '../sdk'
import { storeJson } from '../fileModels/store.json'

const { InputSpec, Value } = sdk

const inputSpec = InputSpec.of({
  host: Value.text({
    name: i18n('Node host'),
    description: i18n('The XBT (BLAKE2b) node RPC host: an IP or a name this server can reach'),
    required: true,
    default: null,
  }),
  port: Value.number({
    name: i18n('RPC port'),
    description: i18n('The node RPC port'),
    required: true,
    default: 8332,
    min: 1,
    max: 65535,
    step: 1,
    integer: true,
    units: null,
    placeholder: null,
  }),
  user: Value.text({
    name: i18n('RPC user'),
    description: i18n('The user of the node RPC credentials (rpcauth or a cookie)'),
    required: true,
    default: null,
  }),
  password: Value.text({
    name: i18n('RPC password'),
    description: i18n('The password of the node RPC credentials'),
    required: true,
    default: null,
    masked: true,
  }),
  chain: Value.select({
    name: i18n('Chain'),
    description: i18n('The chain the node runs; the signer refuses to start on a different one'),
    default: 'main',
    values: { main: 'XBT main', test: 'test', regtest: 'regtest' },
  }),
})

export const nodeConfig = sdk.Action.withInput(
  'node-config',
  {
    name: i18n('Node connection'),
    description: i18n('The XBT node the signer (and the hub) use: host, RPC port, credentials and chain'),
    warning: null,
    allowedStatuses: 'any',
    group: null,
    visibility: 'enabled',
  },
  inputSpec,
  async () => {
    const n = await storeJson.read((s) => s.node).once()
    return n
      ? { host: n.host || undefined, port: n.port, user: n.user || undefined, password: n.password || undefined, chain: n.chain }
      : {}
  },
  async ({ effects, input }) => {
    if (input.user.includes(':')) throw new Error(i18n('The RPC user cannot contain a colon'))
    await storeJson.merge(effects, {
      node: { host: input.host.trim(), port: input.port, user: input.user, password: input.password, chain: input.chain as 'main' },
    })
  },
)
