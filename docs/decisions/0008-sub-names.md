# 0008: Sub-names (`shop.telmo.cell`)

Status: **Live**, deployed in place by type id in September 2026; the renewal rule of
2026-09-17 below is on chain too.

## Two ways to do this, and why this one

**Aggregated (what `.bit` does).** One cell per parent holding a Sparse Merkle Tree
root that commits to every sub-name. Cheap per name, but it needs an on-chain SMT
verifier in RISC-V, per-leaf replay protection, and, the killer, an **off-chain
service to hold the sub-name data**, because a root commits without storing. `.bit`
answers that with their own servers.

**One cell per sub-name (chosen).** A sub-name is an ordinary AccountCell whose label
contains a dot. No new cryptography: the only change is an authorization rule.

The deciding argument is not technical. Cells' distinguishing property today is that it
needs no operator and no backend at all, reads and writes are client-side against the
chain. The aggregated design would reintroduce exactly the dependency that property is
about, and turn the pitch into "no operator is needed, except for sub-names".

**The trade-off, stated plainly:** one cell per sub-name means each costs the same
refundable rent as a name (240 CKB flat since [0015](0015-cell-size.md), 250 when this
was written). That is anti-squatting at small scale
and prohibitive at large scale. Issuing `user123.app.cell` to ten thousand users is not
viable this way, and that is the day the SMT becomes worth its cost. Building it before
that day is building the hard half for a problem we do not have.

## The rule

The charset now allows `.`, with each dot-separated part obeying the original rule
(1..=40 total, `[a-z0-9-]` per part, no leading/trailing hyphen, no empty part, so no
leading dot, trailing dot or `..`).

Allowing dots alone would let anyone register `shop.telmo`, so `register` gains one
check. When the label has a parent (everything after the **first** dot):

1. the parent AccountCell must be present as a **cell dep**, a dep must be a live
   cell, so this proves the parent exists, and it leaves the parent untouched;
2. the tx must spend a cell under the **parent's `owner_lock_hash`** (the existing
   `require_owner` pattern, same as edit/transfer);
3. the sub-name's `expired_at` must not exceed the parent's, otherwise a parent could
   lapse and be recycled while its children kept resolving.

Nesting composes: `a.b.telmo`'s parent is `b.telmo`, so each level only ever authorizes
the level directly beneath it.

New errors: `ParentMissing = 40`, `ParentOutlived = 41`.

## What a sub-name is

A full name. It has its own owner (so it can be **given** to someone, or sold), its own
records, its own manager delegate, its own Fiber endpoint and CKB address, its own
expiry, and it can be transferred and renewed. Everything already built applies to it
unchanged. The parent authorizes creation, and since 2026-09-17 every renewal: issuing
`shop.telmo.cell` to someone hands over the records, the payments and the right to sell
it, but its life stays with whoever holds `telmo.cell`.

## Its life is its parent's (decided 2026-09-17, replacing the note below)

Two rules, both on chain: a sub-name may not outlive its parent (at creation and at every
renewal, `ParentOutlived`), and only the parent's **current** owner may renew it
(`validate_renew` requires an input under the parent's `owner_lock_hash`, the same
proof creation requires). So if `brand` changes hands, by sale or by lapsing and being
registered afresh by a stranger, every `x.brand` runs to its own date and then dies unless
the new owner chooses to keep it. A child cannot buy its own future, and nobody can keep a
sub-name alive under a parent whose owner has not agreed to it.

This replaces the property recorded on 2026-09-11 (kept below for the record), which was
the opposite: renewal needed nobody, so the holder of `shop.brand` could renew `brand` for
its owner, then `shop.brand` for themselves, and survive the parent's change of hands. The
cost of the new rule is one signature: a person who holds `shop.brand` and not `brand`
asks `brand`'s owner to renew it, and the SDK takes that owner as `parentSigner` exactly
as `register` does.

### What "nothing after that" used to mean (noted 2026-09-11, the security journal pass 6; superseded above)

A sub-name survived its parent changing hands, including by recycling. `renew` was
permissionless and checked no owner, only that the child did not outlive whoever held the
parent label *then*. So if `brand` lapsed, was recycled and was registered afresh by
someone else, the holder of `shop.brand` could renew it up to the new owner's expiry, and
the new owner could not recycle it before it lapsed, which the holder could always
pre-empt by renewing first. That note called renewal needing the parent's signature the
costlier alternative; on 2026-09-17 it was judged the cheaper one, because the thing it
buys is the rule a person already assumes.

## Where a fee would go

> Overtaken twice. [0009](0009-economics-and-the-upgrade-key.md) introduced a
> registration fee for every name, sub-names included, and
> [0023](0023-a-fifth-for-a-child-and-a-free-year.md) then priced a child at a fifth of
> its parent. The reasoning below is kept because it framed the question; the answer
> went the other way, charging a child less than a root rather than more.

There is deliberately **no fee here**. Today the protocol takes nothing: `price_floor`
is refundable rent that stays in the registrant's own cell, and `renew` is free. If a
protocol fee is ever introduced, sub-name registration is the natural place, the parent
is providing a service, and it would be an output to a treasury lock, checked in
`validate_register` next to the price floor. That is a governance decision with the same
trust shape as T-1 (whoever can change the fee destination matters), so it belongs in
its own decision record, not smuggled in with this one.
