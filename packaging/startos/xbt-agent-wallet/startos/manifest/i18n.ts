// English only for now; the other locales fall back to it (translations are a store-submission step).
export const short = {
  en_US: 'A spending-limited XBT wallet for your AI agents, with a policy you sign',
}

export const long = {
  en_US:
    "Your AI agents pay for services over xbt402 (payment channels on the XBT chain) through this wallet's MCP server. They can only pay the services your policy allows, within its budgets; anything above your threshold waits for your approval, signed with a key that stays in your browser. The keys stay in the signer, sealed on this server; an anchor witness keeps a tamper record of every signature. Needs an XBT (BLAKE2b) node.",
}
