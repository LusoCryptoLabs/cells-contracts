# 0002: Permissionless registration (ENS-style)

Status: **Accepted** (Phase 2). Supersedes the registration/auth parts of
[0001](0001-lock-and-auth-model.md).

## Context

Phase 1 made registration **sequencer-gated**: the type script required the tx to
spend a cell locked by an operator key, and every AccountCell was locked by that
operator. That is the `.bit`/DAS "keeper" model, registration is not independent
of the operator.

We want the ENS property: **anyone can register a name, with no operator in the
loop.** The obstacle is structural. Names are kept unique by a circular linked
list (SPEC §3): registering `x` means **spending the predecessor cell** (consume
it, recreate it pointing at `x`). But the predecessor belongs to someone else (or
to the root). If it is locked by its owner's key, only they can sign, so a
stranger cannot splice in a new name.

## Decision

Separate **system actions** from **owner actions**, the way `das-lock` does, and
make the type script the sole guardian:

- The AccountCell lock is a uniform **always-success** lock (`account-lock`). This
  is safe because a CKB **type** script runs whenever its cell is consumed, input
  *and* output, so `account-cell-type` can never be bypassed.
- **System actions** `register` / `renew` / `recycle` are **permissionless**. For
  `register` the type script forces the predecessor `p → p'` to be preserved
  byte-for-byte except its `next` pointer: `witness_hash`, `expired_at`, owner,
  account label, the cell lock, **and capacity (may not shrink)** are all fixed.
  So whoever drives the tx can do nothing but splice in a well-formed new name, 
  the predecessor's owner cannot be harmed, hence no signature is required of them.
- **Owner actions** `edit_records` / `edit_manager` / `transfer` require the tx to
  spend a cell whose lock hash equals the account's `owner_lock_hash`. Auth is
  delegated to the owner's own wallet lock; `transfer` is the one action that may
  change `owner_lock_hash`.
- **Genesis is singleton-gated.** A type script cannot see global state, so root
  uniqueness is enforced by requiring genesis to **consume a one-time genesis-token**,
  an input whose type hash equals `account-cell-type`'s args (the namespace id).
  The token is a type-id cell (globally unique, unrecreatable, spendable once), so a
  second root is impossible and it cannot be forged. There is **no ConfigCell** (an
  earlier design had one, but it was forgeable, see the security journal H-1). The token *is*
  the one-time authorization. *(Implemented + VM-proven; activates at the next fresh
  deploy. Residual: the type-id upgrade key, the security journal T-1.)*

`owner_lock_hash` moves from the witness into the authenticated `data` header (new
32-byte field at `[80..112]`), so an edit of the records witness can never change
who owns the name. The witness now carries resolution records only.

## Why always-success + comprehensive type script is safe

For any way an attacker might consume your AccountCell:

| Declared action | Your cell's role | What the type script forces |
|---|---|---|
| `register` | predecessor (input) | preserved byte-for-byte except `next`; capacity ≥ |
| `renew` | the cell (in→out) | only `expired_at` grows; owner/lock/witness fixed |
| `recycle` | recycled (input) | requires `since ≥ expired_at`, must be genuinely expired |
| `edit_*` / `transfer` | the cell (in→out) | requires a co-spend under `owner_lock_hash` |

There is no action under which a stranger can move your capacity, change your
owner, or edit your records. The uniform lock means the predecessor-lock-unchanged
check is trivially satisfiable by honest registrants and unspoofable otherwise.

## Consequences

- Registration needs **no operator and no operator signature**. A registrant funds
  the new cell's capacity (CKB-native rent, reclaimed on expiry/recycle) and pays
  the fee from their own inputs; the predecessor's always-success lock needs no sig.
- One extra deployed script (`account-lock`), trivially auditable (`return 0`).
- Front-running is **naive first-tx-wins** in Phase 2 (commit-reveal, à la ENS, is
  a later refinement). Length/charset pricing beyond the capacity floor is deferred.
- Phase 1's omnilock owner-per-cell (decision 0001) is replaced: ownership is an
  identity in `data`, enforced by the type script, not the cell lock. Manager
  delegation (distinct on-chain capability) is still future work.

## Migration notes

`data` layout changed (added `owner_lock_hash`) and the witness shrank to records
only, so this is a **fresh deployment**, code hashes and the data format differ
from the Phase 1 testnet deployment, which is abandoned.
