import { i18n } from '../i18n'
import { sdk } from '../sdk'
import { nodeConfig } from '../actions/nodeConfig'
import { showSetupCode } from '../actions/showSetupCode'
import { nodeConfigured, storeJson } from '../fileModels/store.json'

/** Seed the store on install (defaults from the file model's shape). */
export const seedStore = sdk.setupOnInit(async (effects, kind) => {
  if (kind !== 'install') return
  await storeJson.merge(effects, {})
})

/** The service cannot start without a node: a critical task until the Node connection action is saved. */
export const watchNode = sdk.setupOnInit(async (effects) => {
  const node = await storeJson.read((s) => s.node).const(effects)
  if (!nodeConfigured(node)) {
    await sdk.action.createOwnTask(effects, nodeConfig, 'critical', {
      reason: i18n('Connect the wallet to your XBT node before starting it'),
    })
  }
})

/** After install: the UI asks for a setup code before the owner chooses its password. */
export const taskSetupCode = sdk.setupOnInit(async (effects, kind) => {
  if (kind !== 'install') return
  await sdk.action.createOwnTask(effects, showSetupCode, 'important', {
    reason: i18n('Once the service runs, get the web UI setup code and choose your password'),
  })
})
