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

## 2026-09-27: whose consent counts

Two passes in one day, the second asked to find what the first left open. Every case is
in `tests/tests/owner_consent.rs` and `tests/tests/consent_paths.rs`, red against the
contracts as deployed (the mainnet binaries are kept in `tests/fixtures` for that), green
after, with the honest case beside each.

- **A lock anybody can spend gave the owner's consent.** `require_owner`,
  `require_owner_or_manager`, the commit holder check and the sale lock's seller branch
  took any input under the owner's lock hash as consent. Under the anyone-can-pay lock,
  PW-Lock or Omnilock in anyone-can-pay mode a stranger can spend such a cell by handing
  it back topped up, and so transfer the name, rewrite its records, mint sub-names, or take
  a listed name unpaid. Nobody was exposed: no name and no listing on either network sat
  under such a lock. Now `lets_anyone_spend` in `cells-core` refuses them, by every type id
  they were deployed under and by the data hash of their binaries. It is a list of known
  locks and no more: a new lock of this kind is refused nowhere until it is added, and the
  SDK and app refuse such a lock as owner, manager, seller or holder before a name can
  reach one.
- **A deed's proxy lock looked one lock too shallow.** A name held as a deed (0036) is
  owned by `input-type-proxy-lock` over a Spore, which opens for whoever spends the Spore.
  The first fix judged the proxy lock and never asked what the Spore sat under. Now it
  consents only when the Spore is spent under a lock that consents itself, at most two
  proxies deep.
- **Paying a listing bought any owner action.** The sale lock opens for whoever pays the
  price, and `account-cell-type` took that as consent to anything: a payer could make
  themselves manager, rewrite the records or mint a sub-name under a listed name instead
  of taking it, for exactly the price of buying it. Low, since the seller is paid in full
  and keeps the name; on mainnet as deployed. Now a sale-lock input consents to the
  transfer alone; anything else on a listed name needs the seller's own input.
- **A sale offer named by data hash.** The paid branch of the sale lock now requires
  `hash_type: type`, closing a small fee leak.

Sizes: `account-cell-type` 41,664 to 44,016 bytes, `sale-lock` 17,376 to 18,280. Live on
Pudge since 2026-09-27 (in place, twice).

### The mainnet upgrade, announced 2026-09-27

In place, by type id, so the code hashes and every name stay as they are. Not before
2026-09-28 at 21:00 UTC. The binaries this source builds with the three values in the
README, and what the two code cells will hold:

| contract | bytes | data hash |
|---|---|---|
| account-cell-type | 44,016 | `0x99ea60a4369ed3d596338b66d6818710a1d047758f478dd854dd814b786aa088` |
| sale-lock | 18,280 | `0x57cdfaa46bc62012315f7c64719f01b43accb66bfc091183a751d59309da3068` |

`account-lock` and `price-cell-type` do not change. Until then, and after, `cellula.id/api/verify`
compares what the chain holds with the hashes the resolver was built with; it reads `false`
while the two disagree and `true` once the resolver follows. TRUST.md's mainnet table is
updated when the cells are.

## What has not been looked at

The `between` and `covers` arithmetic was checked in pass 6, re-derived independently in
pass 8, where the independent derivation turned out to be the one that was wrong, and read
a third time on 2026-09-27 where it is used: `tests/tests/account_cell.rs` offers every
cell of a ring to the contract as predecessor, and every pair for recycle, against a model
that sorts and never calls either function, and five deliberately broken copies of the
contract fail it. Genesis runs once because the genesis transaction destroys its type-id
token, which the contract does not itself check; on both networks it did. Sub-name and
commit griefing economics were modelled on 2026-09-27 and one limit is known: a registration
spends the cell of the name just below it in the ring, so whoever can spend that cell can
invalidate a pending registration, and could in principle keep doing so until a commitment
of their own to the revealed label is sixty seconds old. In one run on Pudge the first
replacement was accepted and the registration was still committed 38 s after it was sent;
holding one back needs a replacement accepted before each reveal is proposed, with confirmed
coins every round. Accepted as a limit; what removes it is keeping records and expiry out of
the ring cell, a two-contract change, planned only when volume asks for it.
Of the functions the tests take expected values from, only `registration_fee` and
`sale_fee` compute what the contract enforces, and both are pinned by hand-written figures
at every step. And the wallet locks a name's owner chooses have not been reviewed as code:
what the contracts need from them is that nobody but the owner can spend them, and the
known locks that let anyone spend stop counting as consent with this upgrade.

Found something? Open an issue here.
