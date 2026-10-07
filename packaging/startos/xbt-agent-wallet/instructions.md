# XBT Agent Wallet

A wallet your AI agents pay with, under a policy you sign. Agents connect to its MCP server; they can pay only
the services your policy allows, within its budgets, and anything above your threshold waits for your approval.

## First start

1. **Node connection** (Actions). Enter your XBT (BLAKE2b) node's RPC host, port, user and password, and its
   chain. The service will not start without it.
2. Start the service. When *Wallet ready to pay* shows success, the node is synced and the keys are unlocked.
3. **Web UI setup code** (Actions). Open the *Web interface*, enter the code, and choose your password
   (at least 10 characters).
4. In the web interface, **Setup**:
   - enrol your approval key: it is made in your browser and never leaves it; write down its backup;
   - sign your first policy: which services your agents may pay, the budgets, and the threshold above which
     you approve each payment yourself.
5. **Agents** page (or the *Agent connection* action): give your agent the MCP endpoint and the bearer token.

## Everyday use

- Payments above your threshold appear under **Approvals**; approve or deny them there, signed with your key.
- **Channels** shows the agent's payment channels, their close reports and refunds; **Signatures** the
  signature log and its anchors.
- The token lets an agent pay what your policy allows. If it leaks, open the **Agents** page and rotate it
  there (no restart), or run the *Rotate the agent token* action. Give your agents the new one.

## Optional: the xbt402 hub

*Enable the xbt402 hub* runs a routing hub other wallets pay through. The hub creates a node wallet named
`hub` and shows a receive address on the web UI **Hub** page. Send XBT there; no terminal.

## Password

*Reset the web UI password* forgets the password; the service restarts and *Web UI setup code* gives a new code.
Your approval key and your funds are not affected.

## Backups

StartOS backups include the wallet's sealed keys, their wrapping key, the channels and the signature anchors.
Keep the StartOS backup safe as you would the wallet. The encrypted backup on the web UI's Keys page is the
portable one.
