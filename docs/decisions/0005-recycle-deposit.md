# 0005: Recycle deposit goes to the recycler (keeper bounty)

Status: **Decided** (resolves the security journal **M-1**).

## Question

When an **expired** name is recycled, its locked CKB deposit (the refundable rent,
≥ the length price floor) becomes the recycler's change. Should it instead be
refunded to the name's former owner?

## Decision

**Keep it as the recycler's bounty.** Recycle is a permissionless keeper action: the
recycler pays the fee and does the cleanup, and the reclaimed deposit is the
incentive to do so (cf. keeper/liquidation rewards). This is documented, expected
behaviour, not a leak.

## Why not refund the owner

It is **not technically possible** for the type script to refund the owner. The
AccountCell stores only the owner's **lock-script hash** (`owner_lock_hash`, 32
bytes), not the lock *script* itself. To create a refund output you need the full
script (code hash + hash type + args); a hash cannot be expanded back into a script
on-chain. So "pay the deposit to the owner" cannot be enforced by the contract, at
best a client could *choose* to add such an output, but the type script could not
*require* it, leaving the guarantee unenforceable.

A name is only recyclable **after it has expired** (proven via the absolute-timestamp
`since`). An owner who wants to keep their name and its deposit simply renews before
expiry (permissionless, anyone can pay to renew). Letting a name lapse is a deliberate
release; the keeper who cleans it up earns the rent.

## Consequence

No code change. The behaviour is the intended economic model; documented here and in
the security journal (M-1 → resolved). Future work could add an *optional* owner-refund output
that clients populate by convention, but it cannot be a protocol guarantee.
