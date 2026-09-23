# 0001: Lock & authorization model

Status: **Accepted** (Phase 1). The deferred on-chain owner/manager split was later
realized by decision [0006](0006-manager-and-reverse.md), though **not** via Option C
(a das-lock): authentication is enforced by the type script against lock hashes stored
in cell data, with a records-only manager carried in the v2 data layout. The historical
reasoning below is unchanged.

## Context

A `.cell` account has two roles (SPEC §4):
- **Owner**, transfer the account, assign the manager, edit records.
- **Manager**, edit records only.

On CKB, a cell is mutated only by being spent, and it can only be spent if its
**lock script** passes. The **type script** (`account-cell-type`) decides whether
the resulting state transition is legal. So "authorization" can live in the lock,
the type script, or both. We must decide where owner/manager authentication lives
and which lock secures an AccountCell.

## Options

- **A. omnilock as the owner lock.** Each AccountCell is locked by omnilock holding
  the owner's key (CKB / ETH / BTC / TRON / Doge / …). Spending ⇒ the owner signed.
  The type script does no signature checks; it enforces structural rules and
  lock-transition rules. No on-chain owner/manager split.
- **B. omnilock + manager checked in the type script.** Rejected: a manager cannot
  spend an owner-locked cell, so a type-script-only manager path is unreachable.
- **C. custom das-lock-style lock.** The lock accepts owner *or* manager and tells
  the type script which acted; the type script restricts the manager to record
  edits. True on-chain owner/manager split, the real `.bit` model. Requires
  writing and auditing a multi-chain signature-verifying lock (the hardest single
  component identified in the replication study).
- **D. type-script-only auth, trivial lock.** Rejected: re-implements multi-chain
  signature verification inside the type script, and a permissive lock is a CKB
  anti-pattern.

## Decision

**Phase 1 uses Option A** (omnilock as the owner lock; the type script enforces
structure and lock transitions). **Option C is deferred to Phase 3**, when manager
delegation and full multi-chain auth (incl. passkey) are actually needed.

## Consequences

- **No new cryptography in Phase 1.** Owner auth (any chain) is provided by audited
  omnilock; the type script verifies *transitions*, not signatures.
- The type script's per-action rules become structural and **fully testable** under
  the always-success lock stand-in (we test transitions, not omnilock's signing,
  which is already audited):
  - `edit_records`, owner lock **unchanged**; only `records` change; id / next /
    account / expired_at / owner-role / manager-role unchanged.
  - `transfer`, the **only** action that may change the owner lock; records,
    manager, expired_at unchanged.
  - `edit_manager`, lock unchanged; only the manager role changes.
  - `renew`, everything fixed except `expired_at`, which only grows.
  - `recycle`, target expired past grace (read via `since` / a header dep).
- Tests stay on always-success as the lock stand-in; production deploys omnilock.
  The type script reads input-vs-output **lock hashes** to enforce the rules above.
- The owner/manager roles in the witness are authoritative resolution data in
  Phase 1; their *distinct on-chain capabilities* (manager-edits-but-not-transfer)
  arrive with Option C in Phase 3.

## Migration to C (Phase 3)

Swap the lock from omnilock to the custom lock and have the type script read the
acting role from the lock witness; the structural rules from Phase 1 carry over
unchanged (they already pin which fields each action may touch).
