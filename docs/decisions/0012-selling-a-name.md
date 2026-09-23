# 0012: Selling a name

Status: **Decided 2026-09-05, deployed and proven live**, after weighing the two options: the offer lock, not the hand-to-hand swap. A real name was sold to a
wallet that had never met the seller; the transactions are in
the test-network deployment log (kept with the application, not in this repository). The screens came later and are described at the end.

## The two ways, and why this one

A sale is a swap between two people who have never met. Neither should have to trust
the other, and neither should be able to walk off with both halves.

**The hand-to-hand swap needs no contract at all.** A CKB transaction has many inputs
and many signatures, so the buyer can sign one that pays the seller and takes the
name, and the seller signs it second and broadcasts. Nobody can be robbed, because
until the seller signs nothing moves, and what they sign is the whole transaction or
none of it. The cost is that both people have to be there, and something has to carry
a half-signed transaction between them.

**The offer lock is what makes a listing possible.** The seller lists once and goes
away; a buyer arrives a week later and completes the sale alone. That is the
difference between a marketplace and a chat, and it is the reason it is worth a new
script.

The cost is stated plainly here because [0003](0003-upgradeability-and-governance.md)
made the same point about timelocks: **a bespoke security-critical lock is its own
audit scope**. This one is 60 lines and holds no money of its own, which is the best
that can be said for it.

## How it works

`account-cell-type` authorizes `transfer` by requiring the transaction to spend a
cell under the name's `owner_lock_hash`. It does not care which lock that is. So:

* **Listing** transfers the name's ownership to the sale lock and leaves one small
  cell under that lock, the offer.
* **Buying** spends the offer cell, which runs this script, and transfers the name in
  the same transaction. The type script sees a valid owner authorization; the lock
  sees the seller paid. Neither knows about the other, and there is no instant at
  which one party holds both the name and the money.
* **Cancelling** is the seller spending the offer cell themselves.

`args = seller_lock_hash (32) ‖ price (8, little-endian shannons)`. The price is in
the args, so it is in the lock hash, so it is in what the name's own data records as
its owner. **The asking price is on chain from the moment of listing and cannot be
changed by anybody, seller included, without an act the seller signs.**

## What was easy to get wrong

**One payment, many offers.** Two names by the same seller at the same price share one
lock hash, and a naive "were the outputs at least `price`?" lets a single payment take
both. The first fix counted inputs under *this exact* script hash and demanded
`price × count`, but two *different* prices are two hashes that share the outputs, so
paying the dearer one satisfied the cheaper (its offer cell consumed free). The audit of
2026-09-05 found this; the fix is to **sum what is owed over every one of the seller's
offer inputs, each at its own price** (`owed_over_offers`), so every instance demands the
same total and it cannot be split. Two tests cover it: `one_payment_cannot_sweep_a_cheaper_listing`
and `both_listings_at_different_prices_bought_together`.

**A hostile type script on the payout.** `paid_to` read only a lock and a capacity, so a
buyer could attach a Nervos-DAO-style lockup or a joint-custody type to the seller's or
the treasury's output, meeting the number while the funds were not theirs to spend, an
extortion lever. The audit fix counts **only pure (untyped) outputs** as payment.

**A zero-price listing.** At price 0 the split is zero and the lock unlocked with no
outputs at all. A stranger is now refused at price 0 (the seller can still reclaim the
offer). Live on Pudge, sale-lock upgrade `0x7aa92129…`.

**A frozen name, and why it heals.** Somebody could pay, spend the offer cell, and
not take the name, leaving it owned by a lock with no cell under it and therefore no
way to satisfy `require_owner` again. It costs the attacker the full price to do it,
and it repairs itself: anybody may create a new cell under any lock, so a new offer
cell restores the listing, and spending that one still requires paying the seller.
The seller ends up paid twice and the griefer ends up poorer.

**The offer cell's own rent** (about 82 CKB, the minimum a cell with 40 bytes of args
can hold) goes to whoever completes the sale. It is roughly their transaction cost,
and a seller who minds should price accordingly. Making the buyer return it would be
another rule to get wrong for a rounding error.

**A listed name still expires.** Nothing here pauses the term, so a listing left up
past the expiry can be recycled by anyone and the deposit goes with it.

## The protocol's cut: ten percent, since lowered to one

> Superseded 2026-09-14 by [0025](0025-one-percent-on-a-sale.md): one percent, with a floor of
> one cell. The reasoning below for taking the share from the seller's side, and never on top
> of the buyer's price, is unchanged.

Decided 2026-09-05. `SALE_FEE_PERCENT = 10`, taken **out of the seller's proceeds**,
so a name listed at a thousand is bought for a thousand and the seller receives nine
hundred. This is the second revenue line after the registration fee.

It follows the same rule as the referral in [0011](0011-referrals.md), applied from
the other side: **the advertised price is the price paid.** A referral comes off the
treasury's share so a registration costs the same with or without an invitation; a
sale fee comes off the seller's proceeds so a purchase costs the buyer exactly the
number they were shown. Nothing in this protocol is ever added on top of a figure
somebody has already been given.

The rounding divides before it multiplies, so it can only ever fall to the seller,
and the two shares always add back up to the price.

**A seller who is the treasury owes itself nothing.** The same outputs answer both
sums, so the requirement collapses to the seller's share. That is worth knowing today
because the treasury lock is the same wallet that holds the first names (see
the test-network deployment log (kept with the application, not in this repository)), and it is the same reason the referral refuses the
treasury as an inviter.

The lock is deployed as a **type-id** cell like everything else, so changing the
percentage later is an in-place upgrade at a stable code hash and nothing needs
relisting.

## What the chain taught, which the tests could not

**A cell must pay for its own bytes, so there is a lowest possible price** (the figures here
are as they stood; [0025](0025-one-percent-on-a-sale.md) moved the floor to the seller's own
payout cell). The
protocol's tenth has to exist as an output, and an output under the treasury's lock
occupies 63 CKB. A listing below **630 CKB** therefore cannot be bought: the network
refuses the transaction before any script runs. `minListingPriceCkb()` computes it
from the lock rather than hard-coding a number, and `listForSale()` refuses below it
with that sentence rather than letting somebody discover it as a failed purchase.

**Cancelling a listing failed the first time it ran on chain, and the reason is
worth keeping.** The offer cell holds more capacity than the transaction costs, so
nothing was ever spent from the seller's own wallet, and the lock's whole test for
"the seller is here" is that a cell of theirs is spent. A transaction that happens to
balance proves nothing. `cancelListing` now puts one of the seller's own cells in
deliberately.

**The seller's lock script travels in the offer cell's data.** The args hold a hash,
and a hash cannot be turned back into somewhere to send money. Scanning the chain for
a cell that hashes to it is not a lookup, it is a hope. The data is checked against
the args on read, so a listing that lies about its seller could never be paid and is
not shown as for sale.

## State

Deployed and **proven live** (see the test-network deployment log (kept with the application, not in this repository)). Eleven tests in
`contracts/tests/tests/sale_lock.rs`, and each of the five rules was **run with the
rule removed** to prove its own test goes red: the args length, the seller's way out,
the offer multiplier, the seller's payment, and the protocol's tenth. `listForSale`
(not `list`, which is the read method every screen uses), `buy`, `cancelListing`,
`listing` and `offers` are in the SDK. **The screens are built** (the app):
**Put up for sale** on a name's page (`?do=sell`, price with the floor and the split
shown before signing), the listed state on that page with **Take it off sale**, a
**Buy** box on the public profile that connects a wallet and completes the sale in
one signature (refusing the seller's own wallet), and "for sale · price" badges in
Explore and My names, where a listed name stays visible to its seller even though the
offer lock owns it. **`/market`** is the public page of everything for sale, cheapest
first, wallet-free, and Explore has an "only what is for sale" switch; both are one
read of the offers joined with the names, no registry.

## What is rejected

**An escrow, on-chain or off.** Somebody would hold both halves for a moment, and
that somebody is exactly what this protocol does not have.

**A price in the witness rather than the args.** It would be cheaper to change and
that is the problem: the price a buyer sees has to be the price the chain enforces,
and putting it in the args is what makes those the same thing.
