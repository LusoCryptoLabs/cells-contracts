# Cells: trust and upgrades

What can change, who can change it, and how to check.

## What is, and is not, controlled

The contracts are **upgradeable by a single deployer key** today. This was a deliberate
choice (decision 0009): a CKB-denominated fee schedule and an unchangeable contract
cannot coexist, so the key was kept rather than burned. The cost of that choice, stated
plainly: **Cells cannot claim "nobody controls it."** The holder of the upgrade key can
change the rules. Trust therefore rests on that key and on the transparency below, not on
immutability.

What the key can do: replace the contract code (in place, same code hash preserved for
existing names). What no key can do: take a fee that the contract does not enforce, the
registration fee is required on-chain to land on the treasury, or forge a second root,
genesis consumed a one-time token and cannot run again.

## The upgrade policy

While the key is a single key, upgrades are governed by policy, not by a lock:

1. **Announced ahead.** A rule change is announced with its new code hash published in
   advance, so anyone can review it and, if they disagree, stop relying on the protocol
   before it lands. (This is procedural today; an enforced on-chain timelock is a bespoke
   lock with its own audit scope, on the roadmap below.)
2. **Verifiable at any moment.** The running code is committed and checkable, see below.
3. **The treasury key** is separate from the upgrade key and only receives fees; it cannot
   change any rule. It is a **single** `secp256k1_blake160_sighash_all` key on mainnet, by
   decision rather than by omission, for the same reason the upgrade key is one: a multisig
   of one person's own keys is a backup scheme, not governance. What that exposes is
   revenue, never a name: whoever holds it receives the fees, and cannot take, edit or
   transfer anything. Moving it is a contract upgrade, because its hash is compiled in.

## The price is a ceiling, and one cell may discount it

The registration fee in the contract is the **most** anyone can be charged, and it is part
of the hash-verified code below. Since decision
[0014](decisions/0014-repricing-without-an-oracle.md) one on-chain **price cell** holds a
discount factor that applies to every name length at once, so the dollar price of a name
can be kept roughly steady as CKB moves without an oracle and without an upgrade. Stated
plainly, what that adds and what it does not:

- **The number in force is not in the code.** `/verify` proves the ceiling and the rules
  that bound the discount; the factor itself lives in the live price cell, and the resolver
  reports it on `/health`. Anyone can read the cell.
- **The discount can only lower the fee.** The contract clamps at the ceiling, and if the
  cell is missing or unreadable it charges the full schedule, so a fault costs the payer and
  never the treasury, and nothing can stop registration.
- **A separate pricing key moves it, inside rules the cell's own script enforces:** at most
  a sixteenth per update, at most once every six hours, never below 63 CKB on the 5+ line (the floor is
  set at the size of a treasury output), lock and capacity unchanged. It cannot touch anything else.
- **What a stolen pricing key can do:** walk the price down to the floor over about
  seventeen days, visibly, at most four steps a day, on a cell anyone can watch by its type id.
  That is the same ceiling per day as the old rule of a quarter once a day, in four moves
  rather than one, so an honest keeper can follow the coin (0014, amended). It cannot raise
  the price above the ceiling, cannot take a name, and cannot change a rule.

## Verify the running contract yourself

The live resolver exposes **`GET /verify`**
(`https://cellula.id/api/verify`):
it fetches the on-chain code cells and reports whether they hash to the published,
reproducible-build hashes. Two things it gives you, and one it does not:

- **Change detection (for anyone).** If the deployed code is ever changed or moved, `/verify`
  flips to `verified: false`. So an unannounced upgrade is *visible* to anyone polling it.
- **A committed bytecode.** The exact hashes the running contract must match are published
  here and checked live.
- **Independent source review**, since 2026-09-23: the source is this repository, and the
  hashes below reproduce from it (the README has the command). What is still not done is an
  external audit, and that gap is named, not hidden.

Current verified hashes (blake2b-256 of the on-chain code-cell data, byte-for-byte equal
to a clean local build; the README has the command). One table per network, because
the same source with a different treasury, sale lock and price cell compiled in is a
different binary.

**Reproducing the mainnet build takes three values and one toolchain.** The values are all
public, they end up inside a binary anyone can read off the chain. The toolchain is
`riscv64-unknown-elf-gcc` 13.2.0 and rustc 1.96.0, with the builder's cargo home remapped
to `/root/.cargo` by the Makefile; the README says why, and what clang produces instead. Without them a plain `make build` produces
the testnet binary and the hashes below will not match, which looks like a failed
verification and is not one.

```sh
CARGO_TARGET_DIR=target/mainnet \
  CELLS_TREASURY_LOCK_HASH=57d926a44d83fc13b21ce037b1e31f4223e3c867cfa3f60e1324d5bfd5cd742d \
  CELLS_SALE_LOCK_CODE_HASH=086c8f4e9d4272e3dfbaca399792f730e6604591e87931ee6d67047a3c900879 \
  CELLS_PRICE_CELL_TYPE_HASH=3f1c9a47d666bd0b5f9a4b2b3afd7c20216280dbcfaddd13748780cdfcbb7586 \
  make build
```

The second and third are chicken-and-egg: a type id is not known until the cell exists, so
`account-cell-type` is deployed, then the sale lock and the price cell, then
`account-cell-type` is upgraded in place to know both. Its code hash does not move, so
nothing deployed against it is disturbed. That is what the upgrade on 2026-09-21 was.

#### Mainnet

| contract | data hash | dep outpoint |
|---|---|---|
| account-cell-type | `0xf86bdba9ff22b5018dcb90a22cdb3720cd5ea8868ab94959ac8146a6789aae30` | `0xe9122f59…:0` |
| account-lock | `0xa46c19f2262abc0d0db0de3952b7477792b36b392645e0f60e74637ae3e3f13b` | `0x522c91d3…:1` |
| sale-lock | `0xf1160f64a82e3509211b2903fc54f9f15cbdc4758d058f107608d30727072a93` | `0x192db7b6…:0` |
| price-cell-type | `0x238e74e1d2d5bf8f06f9f4b0bb352c2addd531351a45cfeddf3ff5f6f5662342` | `0xb3d2428e…:0` |

The scripts as the chain knows them:

| | code hash (type id) | hash type |
|---|---|---|
| account-cell-type | `0xd96cee56727a2bb9a21408c154d278df5095fb4b4dcfd50516156424479bfe54` | `type` |
| account-lock | `0x9f0f0ba142b58cba2fe047546cfd8481d5b1769437cd3533e6458b21b61871ab` | `type` |
| sale-lock | `0x086c8f4e9d4272e3dfbaca399792f730e6604591e87931ee6d67047a3c900879` | `type` |
| price-cell-type | `0x97bf5f760cf72f918f13704d7184933b79d4ddc1fd85075762373e531152d4f9` | `type` |

A code hash under `hash_type: type` is the **type id**, not the hash of the binary. The two
are in different tables here because publishing one for the other makes an integration
document unusable, which happened once.

#### Testnet

| contract | data hash | dep outpoint |
|---|---|---|
| account-cell-type | `0x76ed462c0278e2d3f1413ae6ac254210fb72a8cb2f2c87a1d9d5f37d4e06cc27` | `0x57ed78e4…:0` |
| account-lock | `0xa46c19f2262abc0d0db0de3952b7477792b36b392645e0f60e74637ae3e3f13b` | `0x968ec1a8…:1` |
| sale-lock | `0xa8476c83a6752f9894871f780efcc9530d12e392973e9a3e468c4094c71de4d9` | `0x7b2c9f76…:0` |
| price-cell-type | `0x238e74e1d2d5bf8f06f9f4b0bb352c2addd531351a45cfeddf3ff5f6f5662342` | `0xec7c0690…:0` |

## The road to real trust-minimization, honestly

This raises the floor from "a single key can silently rewrite everything" to "a committed,
observable, policy-governed contract." It does not reach trustlessness. The sequence that
would, in order, and the honest reason each is not done:

1. **A multisig with independent signers.** A multisig of one person's own keys is backup,
   not decentralization; the real fix needs credible co-signers, a social step, not a
   technical one.
2. **An enforced on-chain timelock.** A bespoke lock so a change is delayed and exit-able,
   not just announced. New security-critical code, needs its own audit.
3. ~~**Opening the contract source**~~ **Done, 2026-09-23: this repository.** An external audit was
   considered and deliberately dropped as a gate ([0010](decisions/0010-shipping-without-an-external-audit.md)),
   and is still wanted.

The load-bearing blockers for the first two are people and budget, not engineering.

**None of the three holds mainnet back**, decided 2026-09-13. This file said "then mainnet"
until that day, and that was a promise to wait which was not going to be kept, made in the
one document whose whole purpose is that a stranger can rely on what it says. Mainnet opens
with the contracts upgradeable by a single key. What is offered instead of a promise is the
means to check: the policy above, the `/verify` route that reports whether the running
bytecode still matches these hashes, and a watchtower on the code cells, so an upgrade
nobody announced is visible to anybody who looks. The three steps above still happen, in
that order, alongside a live mainnet rather than in front of it.
