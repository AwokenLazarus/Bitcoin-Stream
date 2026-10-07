import { FileHelper, z } from '@start9labs/start-sdk'
import { sdk } from '../sdk'

/**
 * StartOS-side settings (the `startos` volume, which no container mounts): the XBT node connection the owner
 * enters in the "Node connection" action, and whether the optional xbt402 hub runs. xbt-init copies the node
 * credentials into the signer's (and the hub's) secrets on the `main` volume on every start.
 */
const nodeShape = z.object({
  host: z.string().catch(''),
  port: z.number().int().min(1).max(65535).catch(8332),
  user: z.string().catch(''),
  password: z.string().catch(''),
  chain: z.enum(['main', 'test', 'regtest']).catch('main'),
})

const shape = z.object({
  node: nodeShape.catch(() => nodeShape.parse({})),
  hubEnabled: z.boolean().catch(false),
})

export const storeJson = FileHelper.json({ base: sdk.volumes.startos, subpath: 'store.json' }, shape)

export const nodeConfigured = (n: { host: string; user: string; password: string } | null | undefined) =>
  !!n && n.host !== '' && n.user !== '' && n.password !== ''
