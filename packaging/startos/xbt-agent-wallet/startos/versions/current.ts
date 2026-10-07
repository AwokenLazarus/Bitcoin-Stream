import { IMPOSSIBLE, VersionInfo } from '@start9labs/start-sdk'

export const current = VersionInfo.of({
  version: '0.1.0:0',
  releaseNotes: {
    en_US:
      'First local package (AGP-040): the signer, the anchor witness, the MCP server, the web UI and the optional xbt402 hub. Side-load only.',
  },
  migrations: {
    up: async () => {},
    down: IMPOSSIBLE,
  },
})
