# 0023: A fifth for a child, and a free year

Status: **Live on Pudge, 2026-09-11.** Upgraded in place by type id, so the code hash
did not move and every existing name kept validating. Only `account-cell-type` changed,
by 104 bytes; `account-lock` and `sale-lock` rebuilt byte-identical, because nothing
outside the account contract calls the fee.

Proven against the deployed contract rather than the harness, by
a proof script (kept with the application, not in this repository): `p232mn2a.cell` was registered for five years and
charged 20,000 CKB, four years at the list rate, and the chain shows it expiring in
2031; `shop.p232mn2a.cell` was then registered for 1,000 CKB against its parent's 5,000,
and expires inside its parent's term. Both transactions would have been refused with
`InsufficientPrice` by the contract that ran that morning.

The upgrade went first and the app second. That order matters: the contract accepts
overpayment, so the old app quoting the old prices against the new contract merely
overcharged for a few minutes, while the reverse would have had every sub-name
registration refused.

## What was wrong

Two things the schedule in [0009](0009-economics-and-the-upgrade-key.md) did not think
about, found by pricing the product rather than the protocol.

**A sub-name cost exactly what a root name cost.** The fee is read off the label's
length, and `alice.acme` is ten characters, so it fell in the five-plus band at 5,000 CKB
a year, the same as `acme` itself. A company giving a thousand people a name inside its
own namespace would have paid about €4,600 a year for the privilege, which is why nobody
would have. The one feature aimed at organisations was priced as though each of their
users were a stranger buying a name of their own. [0008](0008-sub-names.md) said a fee
would be "the natural place" for sub-names and then left the question open; this answers
it in the other direction from the one that document imagined, by charging less rather
than more.

**A ten-year term earned nothing a ten-times-one-year term did not.** The schedule was
linear, so there was no reason for anyone to buy time in advance and no reason for us to
want them to.

## Decided

**A child is charged a fifth of what its parent is charged, for the same term.** Priced
from the parent's length, not its own:

| Parent | Parent, a year | Each child, a year |
|---|---|---|
| five characters or more | 5,000 CKB | 1,000 CKB |
| four | 20,000 | 4,000 |
| three | 80,000 | 16,000 |
| two | 200,000 | 40,000 |
| one | 500,000 | 100,000 |

The child's own length buys nothing, so `a.telmo` and `warehouse.telmo` cost the same.
That is the point: `a.telmo` is not a one-letter name, it is one name inside somebody
else's, and the thing with scarcity value is the root. A short parent therefore makes
dearer children than a long one, which is the same scarcity argument the root schedule
already makes, applied one level down. Nesting is capped at one level
([0008](0008-sub-names.md)), so there is no compounding and no depth at which a name
becomes free.

**One year in every five is free**: a term of `years` is billed as `years - years / 5`.
Ten years cost eight. Five cost four.

Note the flat steps this creates. Four years and five cost the same, and so do nine and
ten. At each step there is no reason left to buy the shorter term, which is what the
longer term is for. The discount is proportional, so it favours no length over another,
and the referral tenth is taken from what is actually charged, so an inviter is paid on
the discounted figure rather than on a list price nobody paid.

## Why not the other ways

**A flat price per child**, say 500 CKB whatever the parent. Simpler to say, and it
throws away the only thing that makes a namespace worth more than another: a child of
`a.cell` should not cost what a child of `warehousedistribution.cell` costs.

**Free children, paid parent.** Tempting, and it is what an SMT design would eventually
allow, but every child here is a real cell paying real rent, and a fee of zero makes a
namespace an unmetered place to write. The fifth keeps the incentive without making the
feature pointless.

**A discount on the fee rather than on the term.** A percentage off every purchase is a
price cut, which the price cell already does properly and reversibly
([0014](0014-repricing-without-an-oracle.md)). This rewards only the thing that costs
the protocol least to give: money sooner, and a name that stops coming up for renewal.

## What it obliges

- `registration_fee` now takes the label rather than its length, since it must see the
  parent. Both callers in `account-cell-type` pass `account()`, at register and at renew,
  so a child renews at a fifth too.
- the SDK's `codec` module mirrors both rules exactly, and `billedYears` mirrors
  `charged_years`. Every figure in the schedule divides by five, so neither side rounds
  and the two can never disagree by a shannon.
- The register screen offers "10 years, pay 8" in the term list and says why, measured at
  390 pixels: a discount nobody is shown is a discount that sells nothing.
- Shipping order matters. The contract upgrade goes first, then the app. An app quoting a
  fifth against a contract still demanding the whole would have every sub-name
  registration refused with `InsufficientPrice`.
