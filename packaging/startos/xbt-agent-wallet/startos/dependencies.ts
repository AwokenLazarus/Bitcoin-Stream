import { sdk } from './sdk'

// No StartOS package runs an XBT node yet (Start9's bitcoind is the SHA256d chain), so the node is an external
// connection set in the Node connection action. When xbt-compute's node-host package (CMP-099) exists, declare it
// here and offer it next to "external node" (recipe: Support Alternative Dependencies).
export const setDependencies = sdk.setupDependencies(async () => ({}))
