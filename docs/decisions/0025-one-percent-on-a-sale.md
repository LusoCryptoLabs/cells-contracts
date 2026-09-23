# 0025: One percent on a sale, with a floor of one cell

Status: **Live on Pudge, 2026-09-14.** `sale-lock` upgraded in place by type id
(`0xa1f877bd9a932879f144a27cf1642ff4e69559f8282265bec9105e4625813b9a:0`), so the code
hash did not move and any listing would have survived it. Nothing was listed at the
time, checked on the market page first, so no seller's terms changed under them.

`account-cell-type`, `account-lock` and `price-cell-type` were left alone and still
verify byte-for-byte against the source. Only the lock that splits a sale changed.

## What changed

`SALE_FEE_PERCENT` in `cells-core`, from 10 to 1, and then, the same day, a floor under it.
The way it is taken is untouched: the fee comes out of the seller's proceeds and never on
top of the buyer's price, so a name listed at ten thousand is still bought for ten thousand
and the seller now receives nine thousand nine hundred instead of nine thousand.

**The final schedule, after the question "why do I get nothing on a 1,000 CKB sale":**

| band | fee | effective rate |
|---|---|---|
| 6,300 CKB and above | one percent | 1% |
| 630 to 6,300 CKB | a flat 63 CKB | 10% falling to 1% |
| below 630 CKB | nothing | 0 |

The middle band exists because one percent of a small sale is not a small fee, it is an
impossible one: the treasury's share has to be an output cell and a cell cannot hold less
than its own 63 bytes. The bottom band exists because a whole cell taken from a 400 CKB
sale would be a larger share than we would defend anywhere. The two upper bands meet at
6,300 without a step, since one percent of 6,300 is exactly 63.

## Why

Ten percent was never argued, it was assumed, and it survived until there was something
to compare it against. the competition notes (kept with the application, not in this repository) put the number beside `.bit`,
the naming service that has run on this same chain for years: **about 0.03%.**

At ten percent the marketplace we built is the wrong place to sell a name. A seller with
a name worth anything takes the sale somewhere the fee is not a tenth, which means the
transfer happens outside the protocol, the price is never public, and the marketplace
earns ten percent of nothing rather than one percent of something. The fee was set as
though the problem were extracting value from a busy market; the actual problem is that
there is no market yet.

One percent is still more than thirty times theirs. It is not a race to the bottom, it
is leaving the number close enough that using our own marketplace is the obvious choice
rather than a tax on being lazy.

## The floor, which was wrong for a day

The first cut of this raised the smallest listing from about 630 CKB to about 6,300,
because the treasury's share has to exist as a cell and at one percent the price has to
be a hundred times that floor rather than ten. That was reported as a cost of the change
and accepted, and it was neither: **charging less made cheap names less sellable**, which
is the opposite of the point, and seven dollars is not a floor a naming service can
defend.

**Fixed the same day, in the contract.** `sale_fee` now returns zero when one percent
could not be a cell. The alternatives were both worse: demand it anyway and no cheap name
can ever be sold, or round it up to a whole cell and a name sold for 100 CKB pays 63 of
them, a fee of sixty-three percent.

So the floor is now **the seller's own payout cell**, which is the only thing the chain
itself insists on, and it does not move with the fee. It is not one number: 61 CKB for an
ordinary secp256k1 key, 63 for a JoyID one, more for a lock with longer arguments. Lower
than it was before this decision, not higher.

That was measured rather than reasoned, and the first answer given was wrong: 63 was
quoted for everybody because it is the treasury lock's size, and a sale went through at
62. Walking it down on chain found the real edge for that seller at **61**, with 60
refused by name. The sale screen now reads the connected wallet's own lock instead of
showing one figure to everyone, which had it refusing a listing the contract accepts.

It cannot be gamed by under-pricing: the fee is a fraction of what the seller actually
receives, so listing low to avoid it gives up more than it saves. What it leaves is a step
at the threshold, where asking one CKB less saves 63, and that is the price of the floor
existing at all.

**Proven on Pudge, both sides of it**, with a proof script (kept with the application, not in this repository):

| | |
|---|---|
| listed at **10,000 CKB** | sold, seller received **9,900**, treasury **100** |
| listed at **100 CKB** | sold, seller received **100**, treasury **0** |
| listed at **63 CKB** | sold, seller received **63**, treasury **0** |
| listed at **61 CKB** | sold, seller received **61**, treasury **0** |
| listed at **60 CKB** | refused, and the message says why |

Every one of those is `cartaoprova3695.cell`, sold back and forth between two keys. The
first row is the control: without it, "the treasury received nothing" would equally well
describe a fee that had simply stopped working. The last is the other control: without it,
"61 works" would not establish that anything is a floor at all.

## What lowering the floor uncovered

Dropping the floor to the cost of a cell made a listing cheaper than the **deposit** the
seller parks to publish it, and that turned out to be a hole rather than a feature: the
contract handed that deposit to whoever completed the sale, so a name listed under 160
CKB could be taken with no payment at all. It was reproduced as a real sale before it was
fixed. [the security journal](../SECURITY-JOURNAL.md) F-8 has the transaction and the repair; the deposit
now returns to the seller, so a buyer brings exactly the price and a seller receives
exactly the price.

It is recorded here because the two decisions are one story: **a floor that is too high
hides what is behind it.** Four years of a 630 CKB minimum kept a defect unreachable and
therefore unseen.

## What the change taught, which is worth more than the change

**Eight integration tests failed, and every one of them was right to.** The sale-lock
fixtures wrote the split out by hand (`const FEE: u64 = PRICE / 10`), so they tested a
copy of the rule rather than the rule. They now call `cells_core::sale_fee`, which is
`const fn` for exactly that reason, and the fixture price rose to 10,000 CKB so it sits
above the floor the rate implies: a fixture priced below it exercises arithmetic no real
sale can reach.

**The rate lives in two languages, and nothing checked they agreed.** The contract
enforces the Rust constant; the app shows the TypeScript one and builds every transaction
against it. They were both ten by luck, and so were the other twenty-nine.
an SDK test now parses `cells-core/src/lib.rs` and asserts that **every**
constant the SDK also exports holds the same value, which was the right size for this idea;
checking the fee alone by hand was the smallest possible version of it. The contract is the
authority, because it is what the chain enforces, and an expression the parser cannot read
fails the test rather than being skipped.

**A comment changed a contract, which was already known.** the deployment runbook (kept with the application, not in this repository) 3c
has described this since 2026-09-12: panic locations bake source line numbers into the
binary, so moving a line in `cells-core` changes every contract compiled against it.
a script (kept with the application, not in this repository) already answers **MOVED** rather than MISMATCH for it and prints the
byte count; on the day it was two bytes, at `0xdc0` and `0xdd8`, and it was read as an
alarm only because the output was grepped for the words MATCH and MISMATCH.

The doc's own answer is to upgrade the untouched contract in place as well. The choice
here was the other one: the long explanation lives in this file and the comment beside the
constant was rewritten to the line count it already had, so the contract holding every
name was not respun to document a fee it does not charge. Both are legitimate; what is not
legitimate is discovering it by surprise a second time.
