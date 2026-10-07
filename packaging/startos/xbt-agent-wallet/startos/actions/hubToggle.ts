import { i18n } from '../i18n'
import { sdk } from '../sdk'
import { storeJson } from '../fileModels/store.json'

export const hubToggle = sdk.Action.withoutInput(
  'hub-toggle',
  async ({ effects }) => {
    const on = await storeJson.read((s) => s.hubEnabled).const(effects)
    return {
      name: on ? i18n('Disable the xbt402 hub') : i18n('Enable the xbt402 hub'),
      description: on
        ? i18n('The optional xbt402 routing hub is running. Disable it to stop routing.')
        : i18n('Run the optional xbt402 routing hub: other wallets pay through it and it earns the routing fee.'),
      warning: on ? null : i18n('The hub creates a node wallet named "hub" and shows a receive address on the wallet UI Hub page. Send XBT there; no terminal.'),
      allowedStatuses: 'any',
      group: null,
      visibility: 'enabled',
    }
  },
  async ({ effects }) => {
    const on = await storeJson.read((s) => s.hubEnabled).once()
    await storeJson.merge(effects, { hubEnabled: !on })
  },
)
