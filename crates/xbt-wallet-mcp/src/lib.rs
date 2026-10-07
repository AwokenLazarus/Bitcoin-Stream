//! xbt-wallet-mcp: B2's agent-wallet MCP server as one Rust binary (AGP-030).
//!
//! The same ten tools as B2's `agentwallet/mcp_server.py` (b2 `agp-next2` `b4f2fe5`), with the same
//! names, argument schemas, validation, result JSON and errors, over stdio and streamable HTTP. It
//! talks only to B2's signer socket, so it runs in front of the Rust `xbt-signer` or B2's Python
//! signer, and it never holds a key: the signer holds them all, and the approval, recovery, sweep
//! and rotation operations are not tools at all.
//!
//! * [`mcp`]: the protocol, answered as B2's SDK answers it; [`mcp::TOOL_NAMES`], [`mcp::FORBIDDEN`].
//!   AGP-048 adds [`mcp::LN_TOOL_NAMES`] (`ln_pay`, `ln_status`), offered only with `XBT_MCP_LN=1`.
//! * [`args`]: pydantic-compatible argument validation; [`pyrepr`]: Python reprs for its messages.
//! * [`wallet`]: the signer socket, B2's `_pack` (sanitize, refuse key material, print), and the
//!   optional in-process xbt402 payer (`XBT_MCP_PAYER=local`).
//! * [`transport`]: stdio and streamable HTTP.
pub mod args;
pub mod mcp;
pub mod pyrepr;
pub mod transport;
pub mod wallet;
