# 0004: Commit-reveal (anti front-running)

Status: **Implemented & live on Pudge** (in-place type-id upgrade `0x6cddbe65`).
Addresses the `register` front-running vector in the security journal.

## Problem

`register` was naïve first-tx-wins: a name is public in the tx before it confirms, so
a mempool watcher can copy the label and front-run the registrant (pay a higher fee,
land first, grab the name). ENS solves this with a two-phase commit-reveal.

## Design (as built)

Two phases, the second gated on the first having existed for a minimum delay:

1. **Commit.** The registrant pays themselves a **CommitCell** whose whole `data` is
   `commitment = blake2b(namespace_id ‖ label ‖ owner_lock_hash ‖ secret)`
   (`cells_core::commitment`). The label is **not** revealed. No new contract, it is
   an ordinary cell under the registrant's lock; its 32-byte data is the commitment.
2. **Reveal / register.** After `MIN_DELAY`, the registrant runs `register`,
   additionally:
   - spending their CommitCell as an input, with its `since` set to a
     **relative-timestamp ≥ `COMMIT_MIN_DELAY`**;
   - revealing `secret` in the new cell's witness (`witnesses[x].input_type`);
   - the type script (`require_commit`) recomputes `commitment` from the new cell's
     `label` + `owner_lock_hash` + the revealed `secret`, scans the inputs for a cell
     whose data equals it, and checks that input's `since` (relative-timestamp flag,
     value ≥ `COMMIT_MIN_DELAY`).

   The commitment hides the label (a front-runner can't commit to the same name in
   time, their commit would be younger), binds `owner_lock_hash` (they can't reuse
   the victim's commitment, the revealed name still goes to the committed owner) and
   binds `namespace_id` (no cross-instance replay).

## Why the on-chain clock is *not* a header-dep

The original plan needed a header-dep timestamp for `MIN_DELAY` (the same plumbing
deferred for on-chain future-expiry). It turned out unnecessary: CKB's **relative
`since`** with the timestamp metric (top byte `0xC0`) makes *consensus itself* refuse
to mine the reveal until the spent CommitCell is `MIN_DELAY` old. The type script only
has to check the flag and value; the chain enforces the actual elapsed time. (Recycle
already uses the absolute-timestamp `since`, `0x40`, for expiry, same family.) So no
header-dep, no new validator binary, no clock to trust.

`MAX_DELAY` (commit expiry) is **not** enforced on-chain, that *would* need a current
-time reference. A stale commit is simply reclaimable locked capacity, so this is a
hygiene gap, not a security one (front-running protection comes entirely from
`MIN_DELAY` + the hiding/​binding commitment).

## Parameters

- `COMMIT_MIN_DELAY = 60` seconds (`cells_core`, mirrored in the SDK).
- Errors: `CommitMissing = 36` (no matching commit input), `CommitTooYoung = 37`
  (commit `since` not a relative-timestamp ≥ `MIN_DELAY`).

## Surfaces

- **Contract** `account-cell-type::require_commit` + `check_commit_since`.
- **cells-core** `commitment()`, `COMMIT_MIN_DELAY`, `SECRET_LEN`.
- **SDK** `commitment()` (drift-tested vs the Rust bytes), `CellsClient.commit()` +
  `register({ secret, commit })` + `registerWithCommit()` convenience.
- **scripts** a script (kept with the application, not in this repository) (commit → wait → reveal, commit persisted to
  a local file so an immature reveal is safely re-runnable).
- **UI** a two-step Register panel (Commit → maturity countdown → Reveal & register).

## Note on UX

Registration is now two transactions with a ~minute wait between them. The relative
`since` matures on **median-time-past**, which lags real time, so the reveal may need
a few retries past the nominal 60 s, clients retry on the `Immature` verification
error.
