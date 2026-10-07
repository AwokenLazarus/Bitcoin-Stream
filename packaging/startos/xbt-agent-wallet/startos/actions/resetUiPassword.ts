import { rm } from 'node:fs/promises'
import { i18n } from '../i18n'
import { sdk } from '../sdk'

/** Forget the web UI's password hash; on the next start the UI asks for a new setup code (Web UI setup code). */
export const resetUiPassword = sdk.Action.withoutInput(
  'reset-ui-password',
  {
    name: i18n('Reset the web UI password'),
    description: i18n('Forget the web interface password. The service restarts and the UI asks for a new setup code.'),
    warning: i18n('Anyone with the new setup code can choose the password. Your approval key and the wallet are not affected.'),
    allowedStatuses: 'any',
    group: null,
    visibility: 'enabled',
  },
  async ({ effects }) => {
    await rm(sdk.volumes.main.subpath('ui/password.scrypt'), { force: true })
    await effects.restart()
    return {
      version: '1',
      title: i18n('Web UI password reset'),
      message: i18n('Run Web UI setup code once the service is running again.'),
      result: null,
    }
  },
)
