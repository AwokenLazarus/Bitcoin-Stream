import { i18n } from '../i18n'
import { sdk } from '../sdk'

/**
 * The web UI's own first-run login: until a password is set it asks for a one-time setup code, which it
 * writes to the `main` volume (ui/setup-code). The owner then picks the password in the UI, and only its
 * scrypt hash is kept; the setup code is deleted.
 */
export const showSetupCode = sdk.Action.withoutInput(
  'ui-setup-code',
  {
    name: i18n('Web UI setup code'),
    description: i18n('The one-time code the web interface asks for before you choose its password'),
    warning: null,
    allowedStatuses: 'only-running',
    group: null,
    visibility: 'enabled',
  },
  async () => {
    const code = await sdk.volumes.main.readFile('ui/setup-code', 'utf8').then(String, () => '')
    if (!code.trim()) {
      return {
        version: '1',
        title: i18n('Web UI setup code'),
        message: i18n('The web UI password is already set. To choose a new one, run Reset the web UI password.'),
        result: null,
      }
    }
    return {
      version: '1',
      title: i18n('Web UI setup code'),
      message: i18n('Open the web interface, enter this code, then choose your password (at least 10 characters).'),
      result: { type: 'single', name: i18n('Setup code'), description: null, value: code.trim(), masked: false, copyable: true, qr: false },
    }
  },
)
