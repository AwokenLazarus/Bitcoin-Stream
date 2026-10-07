# What an app that depends on the XBT node gets (the contract with xbt-compute's node-host app, CMP-098:
# it exports the same names). umbrelOS sources every installed app's exports.sh before it runs compose.
# derive_entropy is umbrelOS's helper (a per-box secret derived from the box seed and this label).
export APP_XBT_KNOTS_NODE_HOST="lazarus-xbt-knots_node_1"
export APP_XBT_KNOTS_RPC_PORT="8332"
export APP_XBT_KNOTS_CHAIN="main"
export APP_XBT_KNOTS_RPC_USER="xbt"
export APP_XBT_KNOTS_RPC_PASS="$(derive_entropy "lazarus-xbt-knots-rpc-${APP_XBT_KNOTS_RPC_USER}")"
