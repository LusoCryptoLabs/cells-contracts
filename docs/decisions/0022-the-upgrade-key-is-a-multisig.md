# 0022: The upgrade key is a multisig

Status: **Rehearsed and proven on Pudge 2026-09-11, then reverted the same day; the
upgrade key is a single key again.** The four type-id code cells (`account-cell-type`,
`account-lock`, `sale-lock`, `price-cell-type`) were held by a 2-of-3 CKB system
multisig for a few hours: a one-of-three upgrade was refused by the chain, a two-of-three
upgrade landed, a full signing round with holders on separate key files landed, and then
the multisig signed everything back under the CELLS key (`0x968ec1a8…`) and its funds
were swept there (`0x97b84a09…`).

**Why reverted.** With all three keys on one machine in one file the
arrangement was one key with extra steps, and the honest alternatives were to split the
keys across places (friction on every fix while the contract is still moving) or to say
"single key" and mean it. For testnet, with fixes still landing daily, the second is
right. What the rehearsal bought is kept: the handover, the round and the holder-side
signer all work and are in the repo, so moving to real holders is a rehearsed transaction
rather than a first-time event. T-1 in [the security journal](../SECURITY-JOURNAL.md) stays a single key,
said out loud, and the section below is the record of how the move works when it is
wanted.

## What it is

The audited, genesis-frozen `secp256k1_blake160_multisig_all`, the v2 deployment CCC
knows as `Secp256k1MultisigV2` (`0x36c971b8…`, `data1`). No custom lock, which is what
[0003](0003-upgradeability-and-governance.md) asked for and [0009](0009-economics-and-the-upgrade-key.md)
repeated: the system multisig gives M-of-N and a one-shot `since` cliff, and anything
fancier (a recurring per-upgrade delay) is bespoke security-critical code with its own
audit. The delay stays procedural: upgrades announced ahead, the watchtower watching.

Lock args are `blake160(S ‖ R ‖ M ‖ N ‖ pubkey_hash × N)` with `S = 0`, `R = 0`,
`M = 2`, `N = 3`. Address `ckt1qqmvjudc…u58spc`, lock hash `0x98399b60…f7fd`. The
script that speaks it is a proof script (kept with the application, not in this repository); CCC has no multisig signer, so the
witness is assembled there on top of CCC's sighash helpers.

## What it is not, said plainly

**All three keys are ours.** They live in the multisig key file, made fresh on the
day. 0009 calls this backup with extra steps, not governance, and that is what it is: it
protects the protocol from a lost key, it protects nobody from us. The mechanism is what
was being rehearsed. On mainnet the N keys are held by named people who are not the
same person, or the section in the mainnet runbook (kept with the application, not in this repository) that says "single key" stays
true and says so.

## How it was moved

1. **Preflight on a throwaway cell** (a script (kept with the application, not in this repository)), before any code
   cell was at risk, because the last upgrade key was lost once and an unspendable lock
   here would be the same loss with better paperwork. It caught a real bug: the script
   hashes the witness with the lock field set to *the multisig script followed by zeroed
   signature slots*, not to all zeros, so a message computed over a plain placeholder
   verifies against the wrong bytes. The lock refused with code 2; fixed; then one
   signature refused (control) and two spent (`0xdafd8cb7…`), given last-key-first so
   order is shown not to matter.
2. **Handover** (a script (kept with the application, not in this repository)), tx `0x7fc815af…`: all four code cells
   spent by the old single key and recreated byte for byte with the same type-id args
   under the multisig, in one transaction. No code hash moved, every live name kept
   validating; the four dep outpoints moved, hence repoint, watchtower, app, resolver as
   after any upgrade. 2,000 CKB funded to the multisig for its own fees (`0x01f7e24b…`).
3. **Proof** (a script (kept with the application, not in this repository)): the same in-place respend of
   `account-lock` signed by one key, refused by the chain (`Inputs[0].Lock` validation
   failure); signed by two, landed (`0x501c9b77…`). Same bytes, so
   a script (kept with the application, not in this repository) still MATCHes and only `lock.dep` moved.

`deployment.json` now carries `upgradeLock` (kind, m, n, address, lock hash, the three
public key hashes, the handover tx), and every upgrade script signs through
a script (kept with the application, not in this repository) when it is present, or with the single key when it is not, so the same
scripts serve both a fresh single-key testnet and this one.

## What changes for operations

- **Back up the multisig key file in more than one place, now.** It is the upgrade
  key. `cells.key` no longer is; it keeps the deployer's other duties (genesis on a fresh
  namespace, funding).
- An upgrade needs two of the three files present on the machine that builds the
  transaction; today that is one machine, on mainnet it is a signing round.
- Fees for upgrades come from cells under the multisig, not from any personal key. Keep
  it funded; the watchtower's `cells-upgrade-wallet` watch now points at it.
- Everything in the deployment runbook (kept with the application, not in this repository) sections B, C and D is unchanged except which lock signs.

## What stays open

Real holders (the mainnet question). The move to a post-quantum multisig
([0016](0016-post-quantum-owner.md)) before 2030, which the SPHINCS+ lock supports
natively and which will be the same handover shape as step 2 above, with a different
a script (kept with the application, not in this repository). And the price cell's key, which is deliberately not this key and
deliberately not a multisig: it can only move a discount a sixteenth every six hours.
