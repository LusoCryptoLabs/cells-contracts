# 0015: how many bytes a name is allowed to cost

**Status:** accepted 2026-09-09; **implemented and live on Pudge** the same day as a fresh namespace (deploy `0x50b82bc3…`, genesis `0x561ced5a…`, see the test-network deployment log (kept with the application, not in this repository)). The mainnet genesis uses this layout.
**Date:** 2026-09-09

## Why now and not later

On CKB a cell must hold its own size, one byte to one CKB, and that is consensus rather
than anything we choose. So the capacity a name locks is decided entirely by how many
bytes its cell occupies, and the only lever we have is the layout.

A layout change is either a fresh namespace or a versioned v3 in which **every name
already registered keeps its old size for ever**. There is no migration that shrinks a
cell somebody else owns. So the window for this is now: after mainnet, every byte not
removed is permanent for every name in the system.

The pressure is not today's price. At €0.00096 a CKB an AccountCell costs about 22
cents. The question is what happens at ten or a hundred times that, where a name that
sells for five dollars a year asks the buyer to lock two hundred.

## What a name occupies today

Measured against eight live cells on Pudge, whose labels run from 4 to 13 characters.
The 218 below is the label-independent part and the model is exact on every one of them:
predicted `joao` 222 and the chain holds 222, `telmo` 223 and 223, `gamer.tecmeup` 231
and 231. Adding the label length is arithmetic, not extrapolation.

**The endpoint is measured too, without registering it.** No cell has ever existed
between 33 and 40 characters (until the flat floor landed those lengths were
unregisterable), so it was checked by asking the node directly: a real-shaped 40-character
v2 AccountCell submitted to `test_tx_pool_accept`, which runs the full verifier and
broadcasts nothing, was refused at 290 CKB with `InsufficientCellCapacity` and the node's
own figure, **291 CKB occupied**, and cleared the capacity check at 291. Repeat it with
`node a proof script (kept with the application, not in this repository).

| | bytes | |
|---|---|---|
| capacity field | 8 | consensus, fixed |
| lock `code_hash` + `hash_type` + args | 33 | consensus, fixed (account-lock takes no args) |
| type `code_hash` + `hash_type` | 33 | consensus, fixed |
| type args, the namespace id | 32 | candidate |
| data: `witness_hash` | 32 | candidate |
| data: `id` | 20 | candidate |
| data: `next` | 20 | needed, not derivable |
| data: `expired_at` | 8 | candidate |
| data: `owner_lock_hash` | 32 | candidate |
| **total** | **218** | **plus the label** |

At the maximum label the arithmetic gives 258 for a v1 cell and **291 for a v2**, and
that 291 is the worst case the 300 was chosen to clear. Observed: the node computes
exactly 291 for that cell (2026-09-09).

**Implemented and measured again (2026-09-09).** Under the v3 layout, one shape with the
manager always present, a 40-character name occupies **232 CKB** whether or not it is
delegated: refused by the node at 231 with its own figure, cleared at 232
(a proof script (kept with the application, not in this repository)). The floor is 240.

Of that, **74 bytes are untouchable**: the capacity field and the two script code
hashes are the chain's shape, not ours. A v2 (delegated) cell adds 33 more, a version
marker and a 32-byte manager hash.

## The rule that decides each case

Truncating a hash is safe or not depending on **who chooses the inputs**.

- If an attacker must match a value **somebody else already fixed**, they need a
  targeted second preimage. Against 20 bytes that is 2^160 work. Not a consideration.
- If the same party chooses **both sides**, it is a birthday problem. Against 20 bytes
  that is 2^80, and 2^80 is not a comfortable number: the Bitcoin network gets through
  roughly 2^69 hashes a second, so 2^80 is minutes of that scale of hardware. Different
  hash, but the order of magnitude is the point.

So: **truncate a field an attacker has to match; never truncate a field an attacker can
grind on both sides.**

## The candidates

### 1. Drop `id` entirely, saving 20 bytes. Recommended.

`id` is not independent data. The integrity check in `main()` already requires
`a.id() == account_id(a.account())` for every non-root cell, so it stores twenty bytes
of something the label determines. Verified against every live name on Pudge, not just
against the contract's claim about itself.

Checked 2026-09-09 against the live namespace: **18 of 18 names**, every id equal to
`blake2b(label)[..20]`. Repeat it with `node a proof script (kept with the application, not in this repository).

The linked list keeps working: `next` is stored (it is genuinely independent), and a
cell's own id is recomputed from its label wherever `covers`/`between` need it.

**Condition, not convention:** `blake2b("")[..20]` is `0x44f4c69744d5f8c55d642062949dcae49bc4e7ef`,
not `ROOT_ID`. The derivation must map the empty label to `ROOT_ID` explicitly, or
genesis fails and the root's "lo == hi covers everything" breaks. Every raw-offset reader
moves with it, including the resolver, which reads the id from historical outputs by
offset, and `parseAccountLite`, which must hash every cell it scans.

Cost: a few extra blake2b of at most forty bytes per transaction. Cycles are cheap;
twenty CKB locked for ever is not.

This is the largest single saving and the only one whose safety is a fact rather than an
argument, because the invariant is already enforced on chain.

### 2. Namespace id in the type args, 32 to 20. Recommended.

What it protects: the namespace's identity, and with it H-1 (genesis must consume the
one-time token whose type hash *is* the namespace).

To merge into an existing namespace an attacker must mint a genesis token whose type
hash truncates to ours. Type-id args derive from an input outpoint they choose, so they
can grind freely, but the target is fixed: 2^160. At genesis there is no target yet, so
there is nothing to attack.

### 3. `owner_lock_hash`, 32 to 20. Recommended.

This is the authorisation identity: `require_owner` looks for an input whose lock hash
equals it.

To take a name, an attacker needs a lock whose hash truncates to the victim's twenty
bytes. Lock args are free, so grinding is available, but the victim's hash was fixed
before the attack: 2^160.

Precedent worth noting: CKB's own secp256k1 lock identifies a key by `blake160(pubkey)`,
so the ecosystem already treats 160 bits as sufficient for identity.

The same argument covers `manager_lock_hash` on v2 cells, twelve more bytes there.

**Condition, and this one was missed in the first draft: two guards fail OPEN under a
naive truncation.** Both compare the stored owner against a full 32-byte hash, and a
20-byte value never equals a 32-byte one, so the refusal silently never fires:

- `reject_cell_lock_authority` (`hash == &cell_lock[..]`): an owner equal to the
  account-lock hash's prefix is accepted. With `require_owner` prefix-matching, **any
  AccountCell input then authorises**, and the L-1 "public property" hole reopens:
  anyone edits, transfers and sub-names any such name.
- `referral_discount` (`owner != &TREASURY_LOCK_HASH[..]`): the treasury named as
  inviter is no longer refused, so the fee output counts as fee and as cut.

Everything else fails closed (`Unauthorized`, `CommitNotOwned`, TypeScript `===`
against a 32-byte `script.hash()` going false). So the cryptographic argument stands and
the change is **safe only if every comparison site is rewritten in the same change**,
above all those two; done piecemeal it is the worst bug in the project's history, back.
`commit()` must also truncate the owner it hashes, or no reveal ever matches, and the
offers map must be keyed by the truncated hash.

### 4. `expired_at`, 8 to 5. Safe, and probably not worth it.

Five bytes of seconds runs for about thirty-four thousand years. No security content at
all, purely an encoding choice, and the only risk is an off-byte in parsing, which is
mechanical and testable.

Three CKB. Take it only as part of a layout change being made anyway; it is not a reason
to make one.

### 5. `witness_hash`, 32 to 20. **Recommended against.**

This is the one that fails the rule above, and it is worth being explicit because it
looks identical to the other two.

A third party substituting a records payload needs a targeted second preimage, 2^160,
same as the others. But **the owner chooses both sides**: they can grind two payloads
sharing a truncated hash for 2^80, publish one, and later present the other to anyone
who verifies a supplied payload against the cell rather than reading the creating
transaction. That is a misuse of the API, but a hash that only holds when everybody uses
it correctly is not doing its job.

Twelve CKB is not worth turning a preimage argument into a birthday argument. If the
bytes are truly needed, 24 bytes (2^96) is the compromise; 32 is the honest answer.

**The independent review disagrees, and its argument is recorded rather than
resolved.** The record author already has unrestricted `edit_records`, and a transfer's
witness is supplied by the buyer, so a seller cannot plant a twin: a collision buys the
owner nothing they cannot already do on chain, and strangers face 2^160 either way. On
that reading it is SAFE WITH CONDITIONS and the objection above shrinks to a footgun for
an integrator who verifies a supplied payload without reading the creating transaction.
Both readings are defensible; the difference is whether a hash's guarantee may depend
on its consumers using it correctly. Left as a judgement call worth twelve CKB.

### 6. A version byte at offset 0. Recommended, and not a saving.

Suggested by the independent review. The v1/v2 rule today rests on "a valid label's
first byte is never 0x02", read at offset 112, and there is no version field before
that, which is exactly why this change is a redeploy rather than an upgrade. Since the
redeploy is forced anyway, one byte at offset 0 removes the dependence on the label
charset and makes the **next** layout change an in-place upgrade. One CKB, spent once,
for the option to never do this again.

## What this adds up to

| | v1 occupied | v2 occupied | worst case (v2, 40 chars) |
|---|---|---|---|
| today | 218 + label | 251 + label | 291 |
| with 1, 2, 3, 4 and a version byte | **172 + label** | **193 + label** | **233** |

**And occupied size is not what anyone pays.** The first draft framed this as "$227 to
$180", which is wrong in a way the independent review caught: `price_floor` is a flat
300 CKB and every name locks the floor, whatever its cell measures. Shrinking the cell
frees **nothing** on its own. What the layout change does is make a lower floor
possible: with the worst case at 233, the floor can drop from 300 to about **240**, and
*that* is the user-facing number, a fifth off what a name locks. The two decisions are
one decision and must be made together.

Also corrected from the first draft: nothing is "freed today". The layout has no version
field before byte 112 and `parse` reads fixed offsets, so this is a redeploy, not an
upgrade, and no existing cell shrinks. a proof script (kept with the application, not in this repository) said otherwise
and has been fixed.

**And that does not solve the problem in the title.** A fifth off is worth having and is
nearly free, but if CKB goes up a hundred times, a name still locks a sum no ordinary
person will put down for a five-dollar product. The structural answer is aggregation:
one cell holding a Merkle root, names as leaves, per-name cost near zero. What that
costs is the thing we currently sell, a name that is a cell you own, and it reintroduces
the sequencer and the data-availability assumption decision 0002 removed. That is a
different product and belongs in its own decision, informed by Liquid Cells and
Optimistic Cells, which already carry both halves.

The reframe that matters commercially: the deposit is **refundable**, so a holder does
not lose when CKB rises, they hold an appreciating asset and get it back. The damage is
entirely on the other side, the entry barrier for someone who does not own CKB yet. The
price cell (decision 0014) already keeps the *fee* near five dollars as the price moves.
Nothing can do that for the deposit, because the deposit is bytes rather than policy.

## What a test can prove here, and what it cannot

Being clear about this, because "the tests pass" would be exactly the false confidence
[AUDIT-PLAN.md](../AUDIT-PLAN.md) exists to prevent.

**Testable, and required before any of this ships:**
- that `id` is derivable: asserted against every live name on chain, and as a property
  test over random labels;
- that any new encoding round-trips, including at the boundaries (empty label, forty
  characters, the root sentinel, v1 against v2);
- that every existing invariant still holds, with the controls the suite already has.

**Not testable by this suite, and this is the important one:** whether a cell clears
CKB's minimum capacity. That rule lives in the **node**, not in the script.
`ckb-testtool` runs script verification, so a VM test registering a 40-character name at
300 CKB would pass whatever the number was, and would prove nothing about what a real
node accepts.

That is not an oversight, it is why the 33-to-40 gap survived for months with a green
suite: everyone was testing the half that was working.

**What does settle it, measured:** `test_tx_pool_accept` runs the full contextual
verifier and broadcasts nothing. It refused a 100 CKB cell carrying 200 bytes with
`InsufficientCellCapacity` and the exact occupied figure, and accepted the same cell at
300. `estimate_cycles` does **not**: it accepted the undersized cell and returned cycles,
so it is scripts-only like the suite and must never be used as a validity check. Since
the capacity verifier runs before the scripts, a real-shaped cell can be measured at
zero cost by finding the capacity at which the error changes from capacity to script,
which is what a proof script (kept with the application, not in this repository) does.

**Also not testable:** the work factors. 2^160 is an argument from the hash's properties,
not a demonstration, and no green suite establishes it. Each truncation above stands or
falls on the paragraph next to it, and those paragraphs are what an external reviewer
should attack first.

## Second opinion, 2026-09-09

An independent review, given the code and the five changes and forbidden from reading
this document or the audit plan, so that its reasoning was its own. It agreed on 1, 2
and 4; agreed on the cryptography of 3 and found the two fail-open guards above, which
the first draft had missed; disagreed on 5, as recorded; and caught that the first
draft's headline conflated occupied size with what a name locks, and that "freed today"
was impossible. It also verified by reading the ckb-testtool and ckb-verification
sources that the VM suite never constructs the contextual verifier where CKB's
capacity rule lives, which the section below had asserted from reasoning.

Its full report is reproduced verbatim in [reviews/0015-second-opinion.md](../reviews/0015-second-opinion.md). What it could not determine: the cycle cost of
deriving the id per parse, and the practical cost of a 2^80 blake2b collision over
record-sized payloads, neither of which changes the verdicts.

## Decision

Proposed: take 1, 2, 3, 4 and 6; leave 5 as the recorded judgement call. Rewrite every
comparison site under 3 in the same change, with the two fail-open guards tested first.
**Lower `price_floor` to match**, or the change frees nothing. Fix the layout before the
mainnet genesis, since there is no second chance at it.

The worst case the choice rests on has been observed rather than computed (291 CKB,
above), at no cost and without a registration, so there is no open measurement left.
What remains open is the decision itself.
