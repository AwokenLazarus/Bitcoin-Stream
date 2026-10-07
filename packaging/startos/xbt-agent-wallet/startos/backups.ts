import { sdk } from './sdk'

/**
 * Both volumes: `main` holds the signer's sealed keys with their wrapping key, the witness's anchors, the
 * channels, the ledgers and the UI's login hash; `startos` holds the node connection. A StartOS backup is
 * encrypted with the server's master password. On restore, xbt-init (every start) re-applies the owners.
 */
export const { createBackup, restoreInit } = sdk.setupBackups(async () => sdk.Backups.ofVolumes('main', 'startos'))
