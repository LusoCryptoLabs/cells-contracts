# Security

What has been looked at, what was found, and what is still open. The full record, pass by
pass with the transactions that reproduced each finding, is
[SECURITY-JOURNAL.md](SECURITY-JOURNAL.md); the plan the fifth pass ran against is
[AUDIT-PLAN.md](AUDIT-PLAN.md).

**No external audit has been done**, and none gates mainnet
([0010](decisions/0010-shipping-without-an-external-audit.md) says why, and what replaced
it). There is no bug bounty. What exists is nine internal adversarial passes between June
and September 2026, each held to one rule: a finding is a transaction the VM accepted and
should not have, reproduced against the deployed binary before anything was changed, fixed
with a test that fails on the old code, and a control beside it. A green suite proves
nothing on its own; several of the entries below sat behind tests that could not fail.

## Findings in the contracts

| id | severity | status | in one line |
|---|---|---|---|
| H-1 | High | fixed | the config cell was forgeable, so a second root could be minted and a name registered twice |
| R-1 | Critical | fixed | the root sentinel could be recycled, after which any label could be minted at id zero |
| R-2 | Critical | fixed | a commitment is public the moment it lands; anyone could copy it and front-run the reveal |
| R-3 | High | fixed | a manager could be installed at registration, outside the commitment |
| R-4 | High | fixed | capacity was unguarded on every action but register, so a stranger could take a name's rent |
| R-5 | Medium | fixed | genesis never pinned the root's shape |
| poisoning, 2026-09-05 | Critical | fixed | a new name could wear an unspendable lock and freeze its id range for ever |
| sale-lock, 2026-09-05 | High | fixed | one payment swept a cheaper listing by the same seller; a typed output counted as payment; a zero-price listing unlocked free |
| M-2 | Medium | fixed | recycle trusted the ring instead of checking the immediate successor |
| L-1 | Low | fixed | an owner of zero, or of the always-success lock, made a name everyone's |
| L-2 | Low | fixed | a name could be registered already expired |
| F-3 | test only | fixed | the harness could not express a short cell claiming the newer layout |
| F-5 | Medium | fixed | one sale fee answered two sellers |
| F-6 | Medium | fixed | the fee could be paid into a cell the treasury cannot spend |
| F-7 | Low | fixed | a manager of zero was accepted |
| F-8 | High | fixed | a buyer could pay the seller with the seller's own listing deposit; found by measuring a real sale, not by reading |
| F-9 | Medium | fixed | one treasury output answered a registration and a sale in the same transaction |
| P7-1 | Info | fixed in source | genesis accepted a root with an owner; unreachable, the token is spent |
| P7-2 | Low | fixed | a cancellation beside a purchase was charged as a sale |
| P9-3 | Medium | fixed | a sub-name could renew itself past a change of its parent's owner |
| M-1 | Medium | by design | the recycler keeps an expired name's rent; the contract holds a hash and cannot refund |
| F-1 | Low | open, by design | the anti-self-referral guard cannot tell two wallets from two people |
| F-2 | Info here, High if ignored | open, operational | two namespaces sharing one treasury would each count the same fee; the rule is one treasury per namespace, and mainnet has one |
| F-10 | Low | open | the Rust encoder clamps an oversized length prefix instead of refusing; nothing on chain calls it, and the decoder refuses the result |
| T-1 | High | open, by design | the upgrade key can rewrite every rule; see [TRUST.md](TRUST.md) |

Two critical findings in the off-chain SDK, a signature-object forgery for one wallet type and a
payee-chosen anchor that turned "paid" into a confident "not paid", are in the journal and
not in this table, since that code is not in this repository.

## Three classes worth knowing before reading the code

**A payment sum is safe only against itself.** "Sum the outputs paying lock L and require
at least X" is satisfied once for every script that asks. F-2, F-5 and F-9 are that
mistake in three places, and the fix in each is that one side demands the total.

**A truncated compare fails open.** Twenty bytes never equal thirty-two, so a guard
written that way admits everything. It happened once, in the second half of L-1, and
every compare in the contract now takes twenty against twenty.

**Examples are not properties.** 171 example tests missed F-8. The grid in
`tests/tests/sale_properties.rs` and the eight properties over the account contract exist
because of it, and each was shown to catch the guard it covers by breaking that guard and
watching only it fail.

These, and the rest of what this code taught, are written up with toy scripts and failing
tests in [ckb-script-pitfalls](https://github.com/LusoCryptoLabs/ckb-script-pitfalls).

## What has not been looked at

The `between` and `covers` arithmetic was checked in pass 6 and re-derived independently in
pass 8, where the independent derivation turned out to be the one that was wrong; a third
reading would still be welcome. Sub-name and commit griefing economics were never modelled.
No systematic search was made for tests that assert the same wrong thing the code does.
And nothing here covers the wallet locks a name's owner chooses, which we have not reviewed.

Found something? Open an issue here.
