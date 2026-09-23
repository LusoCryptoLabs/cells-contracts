# 0011: Referrals

Status: **Decided 2026-09-05.** A tenth of every registration fee may go to whoever
brought the buyer in.

Extends [0009](0009-economics-and-the-upgrade-key.md), which built the fee this
splits. Nothing here changes what a name costs.

## What it is

A registration may name an **inviter**: an existing `.cell` name. When it does,
`referral_cut(fee)` (ten percent, rounding to the treasury) is paid to that name's
owner and the treasury is owed exactly that much less.

The buyer pays the same either way. The referral comes out of the protocol's
revenue, not on top of the price, because a growth mechanism that makes the product
more expensive is not a growth mechanism.

Registration only. A renewal is not a new user, and charging the treasury for one
would pay a promoter every year for one introduction.

## How the contract knows who the inviter is

The same way it knows who a parent is: **a cell dep**. A dep must be a live cell, so
presenting one proves the name exists without disturbing it, and the label is unique
by the linked list's own invariant.

Payment goes to the inviter's `owner_lock_hash`, the only owner identity a cell
carries. That is a hash, and a hash does not invert (the same wall as
[0005](0005-recycle-deposit.md) and the CKB address in
0007), so the contract can **check** a payment but never
**build** one. The client therefore needs somewhere to send the money, and the only
honest source is the inviter's own published `address.309`, verified with the same
`isOwner` test the public profile already shows as "paid to the owner's own wallet".

So: **to earn referrals you have to publish your owner wallet's address on your
name.** The app says so on the name's page rather than letting the money quietly go
nowhere.

## Who is refused, and the one thing this cannot do

Two disqualifiers, both in the contract:

* **The treasury.** Otherwise a single output would count once as the fee and once
  as the cut, and every registration on earth would be a tenth cheaper.
* **Anyone who signed the transaction.** Without this, your own change output is a
  referral payment to yourself, and any client could take the tenth silently.

Inviting yourself is covered by the second: `require_commit` already forces the
CommitCell to be held by the new name's owner, so the owner is always a signer here.
An explicit owner check would be unreachable code, and unreachable code is code that
can be wrong without a test noticing, so there is none.

**What this does not do is make self-dealing impossible, and it cannot.** The
contract cannot tell a stranger's wallet from a second wallet of your own. Two
wallets and one name defeat every rule above: register a name to wallet B, then fund
registrations from wallet A and name B's name as the inviter. The tenth comes back to
you.

The honest consequence: **the fee schedule is effectively ten percent lower for
anyone determined enough**, and these rules decide only whether that tenth reaches a
promoter or the sharpest buyer. They make self-dealing deliberate rather than
automatic, which is worth having, and they are not a guarantee, which this file says
out loud rather than in a comment nobody reads.

If that ten percent matters more than the growth, there are two answers and both are
one-line changes: raise the schedule by a ninth so the post-referral price is today's
price, or set `REFERRAL_PERCENT` to zero. Neither is chosen here.

## What was rejected

**An inviter identified by a lock hash in the witness.** That is not a referral, it
is "pay anyone ten percent", which is a discount you hand yourself. Requiring a real
registered name at least means an inviter had to buy one.

**Stacking.** The first qualifying inviter is paid and the scan stops. Several
inviters would only be several wallets belonging to one person.

**Paying the referral at renewal.** See above.

## Where it lives

* `cells_core::REFERRAL_PERCENT`, `referral_cut` (and the same pair mirrored in the
  SDK as `REFERRAL_PERCENT` / `referralCutCkb`).
* `account-cell-type::referral_discount`, with `signed_by` and `paid_to`.
* `CellsClient.register({ inviter })`, which refuses locally when the inviter is not
  registered, is this wallet, or has published no owner address, so the failure is a
  sentence rather than a rejected transaction after the commit has been paid for.
* The app: `?ref=<name>` on the register screen, and the link to hand out on
  `/app/names/<label>`.

## Tests

Six in the VM suite, and each guard was **run with the guard disabled** to prove its
test goes red: the treasury exclusion, the signer exclusion, the payment threshold,
and the requirement for an inviter dep at all. Disabling any one turns exactly its
own test red and leaves the others green; disabling the whole thing turns four red
and leaves the happy path passing.
