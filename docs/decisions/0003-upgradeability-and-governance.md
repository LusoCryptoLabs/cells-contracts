# 0003: Upgradeability & governance (the upgrade key)

Status: **Accepted** (policy), **amended by [0009](0009-economics-and-the-upgrade-key.md)**.
Addresses the security journal **T-1**.

> The choice this file left open ("burn if the protocol is considered done, otherwise
> governance") has been made: **the key is kept.** A fee schedule denominated in CKB
> cannot survive alongside a contract nobody can change, and an audit that finds
> something after the key is burned would find it unfixable. See 0009 for the reasoning
> and for what that costs in what Cells may honestly claim about itself.

## Context

The contracts are deployed by **type-id** (decision 0002 / #5): each code cell
carries a type-id type script, and other cells reference it by that type hash
(`hashType: 'type'`). This is what lets us fix bugs (e.g. H-1) **in place**, redeploy
the *same* type-id with new binary and every existing name keeps validating.

The cost: a type-id code cell can be re-created (upgraded) by **whoever can satisfy
its lock**. So **the code-cell lock *is* the upgrade key**, and its holder can swap
the contract binary and rewrite every rule (steal names, mint duplicates, drain
capacity). Today that lock is a single deployer key (`account-cell-type`,
`account-lock`). That is the largest residual trust point in the system.

This is a genuine tension: **immutable** (trustless, but unfixable) vs **upgradeable**
(fixable, but trusted). The naïve "burn it now" is wrong while findings are open and
no external audit has happened, it would freeze *unaudited* code forever.

## Decision

Stage the upgrade key by maturity:

1. **Testnet / pre-audit (now):** keep the code cells under the **deployer key** so
   bugs (H-1, M-1, pricing, …) can be fixed in place. Upgradeability is a *feature*
   here, and the trust is explicit and documented (T-1).
2. **Mainnet launch:** the deployer key must be replaced by one of, in order of
   preference:
   - **Governance + timelock**, a multisig (or DAO) lock with a mandatory delay, so
     any upgrade is announced and vetoable. Keeps the ability to fix critical bugs
     while removing unilateral control. *Recommended.*
   - **Burn (immutable)**, relock the code cells under a provably-unspendable lock
     (e.g. secp256k1 with an all-zero args, for which no private key is known). Fully
     trustless, but no future fixes, only acceptable **after** a clean external audit.

   Choose burn only if the protocol is considered "done"; otherwise governance+timelock.

3. **Order: apply this LAST.** Locking the contract (burn, or a high-friction
   governance lock) removes the ability to ship further in-place upgrades. So the
   sequence is: finish feature/fix upgrades → external audit → apply any audit fixes →
   *then* lock the upgrade key. Doing it earlier would freeze code that still needs to
   change.

**Caveat on "timelock":** the CKB **system multisig lock** natively supports M-of-N
plus a single `since` *cliff* ("not spendable before time T"), which is audited and
zero-custom-code. A *recurring per-upgrade delay* (every upgrade announced T days
ahead, vetoably) needs a **dedicated governance lock**, itself security-critical and
in-scope for the audit. Prefer the audited system multisig (M-of-N) for launch unless
a recurring timelock is a hard requirement; do not hand-roll an unaudited lock.

## Mechanism

The deploy (a proof script (kept with the application, not in this repository)) sets the lock on the two persistent code cells
(`account-cell-type`, `account-lock`; the genesis-token is consumed at genesis). That
lock is the upgrade key. To change policy, change that lock:

- **deployer key** (current): `lock = <cells key>`.
- **governance**: `lock = <multisig script>` (CKB multisig or omnilock multisig).
- **burn**: `lock = secp256k1(args = 0x00…00)`, effectively unspendable.

To actually upgrade under type-id: spend the code cell (satisfying its lock) and
recreate it at the same type-id with the new binary as data; the type-id type script
permits the continuation, all references (by type hash) stay valid, and dependent
txs pick up the new code-cell outpoint.

## Consequences

- The trust assumption is **explicit and staged**, not hidden: testnet is upgradeable
  by the deployer; mainnet must be governance/timelock or burned.
- Upgrades are **safe by construction** (type-id, no fragmentation) but **must** be
  gated by process (timelock/multisig) before they carry value.
- This decision is the gate item for mainnet, alongside an external audit.
