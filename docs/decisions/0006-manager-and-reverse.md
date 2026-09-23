# 0006: Manager delegation (v2 layout) + reverse records

> The v2 byte layout described here was superseded by v3 ([0015](0015-cell-size.md)): the
> manager is always present, at bytes 78..98, and a version byte comes first. Every rule in
> this record is unchanged.

Status: **Implemented & live on Pudge** (in-place type-id upgrade `0x92f30d50`).
Adds the owner/manager split (deferred from decision 0001) and primary-name reverse
resolution.

## v2 data layout (backward-compatible)

v1 cells end the fixed header at the owner (`[80..112]`) and put the label at
`[112..]`. v2 inserts, before the label, a **version marker** and a
`manager_lock_hash`:

```
[ 80..112] owner_lock_hash
[112]      0x02            ← version marker (v2 only)
[113..145] manager_lock_hash
[145..]    label
```

**Discriminator:** a cell is v2 iff `data.len() > 112 && data[112] == 0x02`. This is
unambiguous, a valid v1 label's first byte is `[a-z0-9]` (never `0x02`), and the root
is exactly 112 bytes. So **every existing v1 cell (root, alice, bob, carol) keeps
validating unchanged**; the contract reads `manager`/`account` version-aware, and for a
v1 cell `manager` **defaults to the owner** (no delegation). The root sentinel can
never be migrated (it has no owner), and never needs a manager, so v1 support is
permanent, by design, not a temporary shim.

## Manager delegation

- **owner**, full control: edit records, transfer, set the manager.
- **manager**, may edit records *only* (a v2 delegate; e.g. a dapp or a hot key).
- **`edit_records`** is authorized by **owner OR manager**; everything but the records
  (incl. owner, manager, version) is pinned.
- **`edit_manager`** sets/replaces the manager, **owner-only**, and migrates a v1 cell
  to v2 in place (so delegation is opt-in; names start simple). The manager cannot
  re-delegate.
- **`transfer`** resets the manager to the **new owner**, so a delegate gains no rights
  across a sale.

VM tests: a manager may edit but a stranger may not; only the owner sets the manager;
transfer rejects a non-reset manager. Proven live: `carol.cell` was migrated v1→v2 and
its **manager** edited records while ownership stayed with the user (the test-network deployment log (kept with the application, not in this repository)).

## L-2: on-chain future-expiry (shipped alongside)

`register` now requires `expired_at ≥ now + MIN_REGISTRATION_TERM` (1 day), so a name
cannot be registered already-expired. "Now" is read from the spent **CommitCell's
block header** (a `header_dep`), the commit is recent, so this is a sound clock with
no new trusted input. (Cheating only self-harms, you'd register a name that is
immediately recyclable, so a loose bound is sufficient; this closes the security journal L-2.)

## Reverse records (primary name)

A wallet's **primary name** lives in a small **reverse-record cell** under the wallet's
own lock: `data = "cells:rev:" ‖ label`. Deliberately **no on-chain SMT and no type
script**:

- A global SMT cell would be a write-contention bottleneck on CKB (one updater per
  block); a per-wallet cell has none.
- It needs no type script because reads are **forward-verified**: `primaryName(addr)`
  reads the claimed label, forward-resolves it, and only returns it if that name's
  owner is the same wallet. A forged reverse record therefore resolves to nothing, 
  trustless without any new contract.

SDK: `setPrimary(name)` (write/replace/clear) and `primaryName(address)` (verified
read). Proven live (the test-network deployment log (kept with the application, not in this repository)). An aggregating SMT index is possible future work but
not required for correctness.

## Surfaces

cells-core (`OFF_MANAGER`/`VERSION_V2`, version-aware `AccountData`, `build_account_v2`,
`MIN_REGISTRATION_TERM`); `account-cell-type` (`validate_set_manager`,
`require_owner_or_manager`, version-aware preservation, the L-2 header clock); SDK
(v2 codec + `setManager`/`editRecords`-as-manager/`setPrimary`/`primaryName`, register
`header_dep`); shipped as in-place upgrade `0x92f30d50` (same code hash).

## The manager may also be the primary name (2026-09-10)

`primaryName` accepted a reverse claim only from the name's owner. Since a name can be
put behind a post-quantum key ([0016](0016-post-quantum-owner.md)), the common case is an
owner that is not a wallet and a manager that is: the app offered those names in its own
picker, wrote the claim, and then never showed it, which is how it was found. The check is
now owner **or** manager, and a claim on a name that answers to neither still resolves to
nothing, proven on chain with all three cases including the forgery.

What it changes about sharing: a manager can already edit the records, which includes
where the money goes, so displaying the name is not the larger power, but it is a power.
The help now says so where access is shared.
