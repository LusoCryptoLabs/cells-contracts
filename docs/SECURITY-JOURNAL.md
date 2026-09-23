# Security journal

Every internal review pass on the contracts, newest near the top and oldest at the bottom,
kept as each was written. The summary is [SECURITY.md](SECURITY.md); the plan the fifth
pass ran against is [AUDIT-PLAN.md](AUDIT-PLAN.md).

Two things to know before reading. The transaction hashes and deploy ids cited inside are
the test network's, across several redeploys of the namespace, and are left as written.
And the oldest sections, from June 2026, say an external audit must precede mainnet: that
gate was dropped on 2026-09-04 ([0010](decisions/0010-shipping-without-an-external-audit.md)),
mainnet opened on 2026-09-21 without one, and those sentences stay because dating a
journal is more honest than rewriting it.

## Audit 2026-09-05 (four adversarial reviews + reproduction): fixes live

A full review (payment requests, sale lock, account-cell-type, functional) found, and
this session **fixed and deployed**, the following. Each contract fix has a VM test and
a control that goes red when the guard is removed; the fixes are live in an in-place
type-id upgrade (account-cell-type `0x2dba4faf…`, sale-lock `0x7aa92129…`, same code
hashes) and proven on-chain.

- **CRITICAL, namespace poisoning.** `validate_register` never pinned the new
  AccountCell's own lock to the always-success `account-lock`, so anyone could register
  a name whose cell wore an unspendable lock; that cell can never be a predecessor
  again, freezing its id-range forever (a uniqueness/availability DoS). The same gap let
  a cell's own refundable rent be counted as the registration fee or the referral cut
  (its lock set to the treasury or an inviter). **Fixed:** every output AccountCell must
  wear the same lock as the input AccountCells (which are the account-lock);
  `CellLockNotAccountLock = 48`. This also makes the L-1 `OwnerIsCellLock` guard fire
  correctly. Proven live in a proof script (kept with the application, not in this repository) (foreign lock → 48; the same
  tx under the account-lock → 36, i.e. past the pin). No live name was ever poisoned.
- **CRITICAL, request forgery for one wallet type (off-chain).** The way the SDK handed a
  JoyID signature object to the verifier let extra keys in that object override the fields
  being verified, so a stranger could forge "signed by the owner" for any JoyID name. **Fixed** in the SDK's `request` module
  (`joyIdSignatureIsHonest` refuses a JoyID signature carrying any key beyond
  `{signature, alg, message}`); regression test; deployed and re-verified refused live.
- **sale-lock, one payment sweeping a cheaper same-seller listing (high).** The
  multiplier counted this exact script hash; two prices are two hashes but share the
  outputs. **Fixed:** sum what is owed over all of the seller's offer inputs, each at its
  own price.
- **sale-lock, a hostile type script on the payout (high).** `paid_to` counted any
  output by lock+capacity. **Fixed:** only pure (untyped) outputs count as payment.
- **sale-lock, a zero-price listing unlocking free (low).** **Fixed:** a stranger is
  refused at price 0; the seller can still reclaim the offer.

Functional issues from the same review (not security, tracked for the app): expired
names buyable/shown as live, the privacy notice undercounting localStorage, the calendar
reminder missing the on-the-day alarm, `?do=` panels rendering before guards, and a
placeholder ETH address published on `telmo.cell`.

## Pass 5, 2026-09-09 (adversarial, plan in [AUDIT-PLAN.md](AUDIT-PLAN.md))

Aimed deliberately at what the four earlier passes could not see: interactions
between validators and script groups, assumptions shared by the code and its tests,
and the economic layer. Nine hypotheses were written down in advance. Three findings,
one of them exploitable and now fixed; the rest closed with reasons.

### F-1 (Low, design limitation): the anti-self-referral guard cannot work

`referral_discount` disqualifies an inviter with `signed_by(owner)`, i.e. one who
spent a cell in the transaction. The commit-reveal forces the **new owner** to sign
(the CommitCell must sit under the owner's lock), but it says nothing about the
inviter. So: hold an existing name under lock `L1`, register under `L2`, pay the cut
to `L1`. `signed_by(L1)` is false, `paid_to(L1)` is satisfied by paying yourself, and
the discount applies. One person, two wallets, a permanent tenth off every
registration.

Nothing on chain distinguishes this from a genuine referral, because the chain has no
notion of a person. There is no code fix: `signed_by` is a speed bump against the
lazy case, not a control. The existing test
`referral_pays_the_inviter_out_of_the_treasury_share` already exercises exactly this
transaction and passes, which is the point, the honest reading of that green test is
"a second wallet earns the discount", not "self-dealing is prevented".

Impact is bounded at 10% of treasury revenue and costs the attacker one prior
registration. Mitigation is economic (cap or drop the referral), not technical. The
comment on `referral_is_denied_to_anyone_who_signed` claiming "inviting yourself earns
nothing" is true only for a single lock and should be corrected.

### F-2 (Info today, High if a second namespace is ever deployed): cross-group fee reuse

`require_treasury` counts outputs by **lock hash alone**, with nothing binding them to
the script group doing the counting. Two `account-cell-type` deployments (different
args, therefore different script hashes, therefore two groups in one transaction) that
share a treasury lock would each independently count the *same* output as their fee:
two registrations, one fee. The same shape applies to `paid_to` for referral cuts.

This is the class that produced two of the previous round's sale-lock findings
(one payment sweeping a second listing, a hostile type script on the payout), reappearing
one layer up. It is **not exploitable today** because only one namespace exists, and it
is **untested** because the harness cannot build a two-namespace transaction. It becomes
live the moment a second namespace is deployed with the same treasury, e.g. a v2
namespace alongside v1. Before any such deployment, bind the fee to the group (a
per-namespace treasury lock, or a marker the output must carry).

**Update 2026-09-09:** this condition now holds on Pudge. Decision 0015 moved the cell
layout and was deployed as a fresh namespace beside the previous one, and both bake the
same `TREASURY_LOCK_HASH`. Acceptable on a test network with play money and stated in
the test-network deployment log (kept with the application, not in this repository); it is exactly why a mainnet redeploy must change the treasury or fix this
first, as the rule above says.

### F-3 (test-only, fixed): the harness made the mistake the contract avoids

`with_ident` in `tests/account_cell.rs` checked for the v2 version marker and then wrote
`data[113..145]` **without checking the cell was long enough**, which is precisely the
out-of-bounds read `AccountData::parse` exists to prevent. The consequence was not a
wrong result but an invisible one: the harness panicked while *building* a short cell
that claims v2, so that transaction shape could not be expressed and the case had never
been tested. Guard added, and the two tests below now exist.

### F-4 (Medium, **fixed**): a payee-chosen anchor turned "paid" into a confident "not paid"

Found by the off-chain half of the pass (H8), in `findPayment`. A payment request
carries an `anchor`, a recent block, and `findPayment` walks the payee's transactions
newest first and stops as soon as one is older than it, on the sound reasoning that a
payment cannot predate the request that asked for it.

The anchor is chosen by whoever signed the request, which is the **payee**, and nothing
validated it against the tip. Set it past the chain head and the very first transaction
examined is already "older than the request", so the walk broke **before comparing a
single fingerprint** and returned `{ payment: null, conclusive: true }`. A real,
confirmed payment reported as absent, with the flag that exists precisely to prevent an
unsafe negative saying the answer could be trusted.

`conclusive` is consumed to stop a second payment, so this is a payer being told, by the
party who receives the money, to pay again. No signature check helps: the payee is the
attacker, and the anchor is inside the bytes they legitimately signed. A non-malicious
version reaches the same place through a request built against another network's tip.

This is the third time in this codebase that **a swallowed or mis-trusted input became a
confident negative answer about money** (the earlier two: a silent catch in the on-chain
check, and `findPayment` skipping unreadable receipts). It is the house failure mode.

**Fixed** in the SDK's `request` module, two changes: a bound nothing on the address has
reached is not a bound and is dropped, so the window decides instead; and a receipt
already in hand is compared against the fingerprint **before** any bound may end the
walk, which costs nothing because the receipt was fetched either way. Two tests in the
new an SDK test, with the control run: both go red with the fix
reverted, both green with it. `findPayment` had **no tests at all** before this, which
is how a function whose entire purpose is not to answer wrongly about money went
unexamined.

### F-5 (Medium, **fixed, live on Pudge**): one sale fee could answer two sellers

Found by a fresh review pass on 2026-09-11 and reproduced in the VM before it was
touched, which is the only reason it is stated as fact.

`sale-lock` summed what the **seller** is owed across that seller's offers, which is
right, and then summed what the **treasury** is owed the same way, which is not. Every
sale-lock instance in a transaction reads the same treasury outputs, so with two sellers
present and neither of them signing, a single fee-sized output satisfied both instances:
each saw enough for its own tenth, and nothing saw the sum. Both sellers were paid in
full. The protocol was short.

Within one namespace it is unreachable, because `validate_transfer` goes through
`one_in_one_out` and a transaction can move only one name. It becomes reachable as soon
as a second namespace shares the sale-lock deployment, since each namespace's type script
sees only its own cells and each would see a well-formed single transfer. That is **F-2's
caveat extended to sales**, and F-2's mitigation does not cover it: F-2 is about two
namespaces sharing a treasury, this is about two namespaces sharing a lock.

**Proven both ways.** Against the deployed contract the new test
`one_fee_cannot_settle_two_sellers` reports "expected a failure, it passed"; with the fix
it passes, and the control `two_sellers_paying_both_fees_is_a_sale` confirms the rule
refuses underpayment rather than refusing two sellers.

**The fix**: the seller's leg stays per seller, the treasury's leg is summed over every
offer in the transaction, so all instances demand one indivisible figure. Same correction
already made a level down for two listings by one seller.

**Status**: shipped. Upgraded in place by type id on 2026-09-11, so the code hash the
names obey did not change: the sale-lock code cell at
`0xc015bc333cdf756e2dad9c1ff82b97c6f5abb636e1a2a8bcd2eea57797d9ce1b:0` now carries
`0x97df7e11213259e45109b322368d6e9ff3afef3d2cbd3758e785a1e9ae3cbf1d`, which
a proof script (kept with the application, not in this repository) matches byte for byte against the local build. The same
upgrade carried the thirty-day grace in `account-cell-type`.

### Closed, with reasons (do not re-spend a pass on these)

- **v1/v2 layout confusion.** Sound. `parse` refuses a cell carrying the v2 marker with
  less than the full v2 header, and `core_fields_unchanged` compares the version-aware
  `account()`, so flipping a long cell's marker moves its label out from under its id and
  is caught. Two new tests:
  `a_short_cell_claiming_v2_is_refused_rather_than_read_past_its_end` (control run: weaken
  the length guard in `parse` and it goes red) and
  `a_long_cell_cannot_be_flipped_to_v2_to_move_its_label` (**control not yet run**).
- **Header binding.** `header_time_seconds` uses `load_header(i, Source::Input)`, bound to
  the block containing that input, so "now" is not attacker-chosen. An older commit only
  ever costs the registrant more, never less.
- **Price cell forgery.** Identified by a compiled-in type-id hash, and every failure path
  (missing dep, malformed data, out-of-band factor) falls back to the full price.
- **Referral paid out of the treasury's own output.** Prevented explicitly
  (`owner != TREASURY_LOCK_HASH`).
- **`paid_to` overflow.** `saturating_add` cannot reach saturation: total CKB supply is
  well below `u64::MAX`.
- **Recycle arbitrage.** No arb at any label length. The annual fee is roughly twenty
  times the refundable deposit in every bracket (5,000 vs 250 CKB at five-plus
  characters, 500,000 vs 5,000 at one), so registering to recycle always loses money.
  Recycling *someone else's* expired name for their deposit remains the intended keeper
  bounty (M-1).
- **Fee arithmetic.** `apply_price_factor` computes in `u128` and clamps `bps`;
  `registration_fee` saturates and `years` is capped at ten; `years_for_term` rounds up,
  which favours the treasury; `referral_cut` truncates by under 1,000 shannons.

**Fixed since (live on Pudge 2026-09-09):** `price_floor` used to sit BELOW CKB's own
minimum-capacity rule above 32 characters, and for any v2 (delegated) name of five or
more, so the contract accepted cells consensus then refused and those names could not be
registered at all. The graduated schedule it came from was described as anti-squatting
and was not: the deposit is refundable, so it cost a squatter nothing, while
`registration_fee` (which does not come back) does that job and still slopes. The floor
was made flat at 300 CKB that morning, clearing the then worst case of 291 (a 40-character v2
name); the v3 layout of decision 0015 brought the worst case to 232 and the floor to 240,
and both the Rust and TypeScript tests now assert the *invariant* against CKB's minimum
rather than the constant, so the next layout change fails there first.

### Not covered by this pass

the SDK's `address` module; sub-name and commit griefing economics (H7); and a systematic
search for tests that assert the same wrong thing the code does (H9), of which F-3 is one
instance found by accident rather than by search. Nor any third-party script: see the
table further down for what each of those has and has not had.

H8 (the SDK's `request` module) **is** covered and produced F-4. Checked and sound there: the signed
message is built key by key so ordering cannot drift; `requestFromJson` validates every
field including a closed set of units; the signature-object hole is guarded and `JoyId` is the
only signType routed to that verifier; every other CCC verifier takes the signature as
bytes rather than spreading it; an unknown signType returns `undefined` from CCC's
switch, which every caller treats as false; `locksForIdentity` returns no locks for wallet
kinds it cannot derive, so verification fails closed; and, above all, **every
destination is read from the name's own records on chain, never from the link**, so a
tampered request cannot redirect a payment. `delegated` is reported and the pay page does
show it.

## Pass 6, 2026-09-11 (a fresh pass, ahead of publishing the contracts)

Run by a reviewer with no memory of the earlier passes, against the full scope in
the original audit brief (since retired), with `the security journal` read first so nothing above was re-reported.
Two findings, both reproduced against the deployed binary before they were touched,
both fixed in the same in-place upgrade; two design notes; three documentation defects
corrected. Suite now 86 VM tests in `account_cell` (was 84).

### F-6 (Medium, **fixed**): the registration fee could be paid into a cell the treasury cannot spend

`require_treasury` and the referral leg's `paid_to` counted an output by lock hash and
capacity alone, never looking at its type script. That is the shape `sale-lock` was fixed
for on 2026-09-05 ("a hostile type script on the payout"), one layer up, and nobody had
asked whether the same question applied here. A registrant attaches an always-fail or a
joint-custody type to the fee output: the contract sees the capacity, and the treasury is
handed a cell it can never spend alone. Nothing is gained by the payer, who still parts
with the CKB, so it is a burn or a ransom lever on what the protocol earns rather than a
theft, which is why it is Medium where the sale-lock case was High.

**Proven both ways.** `register_rejects_a_typed_fee_output` reports "expected a failure,
it passed" against the contract as deployed; with `is_pure_output` applied to both sums it
passes with `TreasuryUnpaid` (42), and the controls (`register_is_permissionless`,
`referral_pays_the_inviter_out_of_the_treasury_share`, `renew_extends_ok`) are unchanged.
The harness gained a `typed` flag on plain outputs, which it could not express before,
the same class of gap as F-3.

### F-7 (Low, **fixed**): `edit_manager` accepted the all-zero manager

L-1 rejects an all-zero owner at `register` and `transfer`; the manager field had no such
check, so an owner could delegate to nobody and lose the delegated path to `edit_records`
until they ran `edit_manager` again. Self-harm only and recoverable, unlike a null owner,
but the guard costs one line and the asymmetry was an accident, not a decision.
`set_manager_rejects_null_manager` fails against the old binary and passes now, with
`set_manager_by_owner_migrates_v1_to_v2` as the control.

### Design notes (reasoned, not reproduced: a single-transaction harness cannot express them)

- **A sub-name outlives its parent's identity.** **Closed 2026-09-17 (P9-3 below):
  renewing a sub-name now requires the parent's current owner.** As it stood: `renew`
  was permissionless and checked no owner, only that a sub-name did not outlive the
  parent *currently* holding the label. So after `brand` lapsed, was recycled, and was
  registered anew by someone else, the holder of `shop.brand` could renew it up to the new
  owner's expiry, and the new owner could not recycle it until it lapsed again, which the
  holder could always pre-empt by renewing. Consistent with decision 0008 as it was
  ("the parent authorizes creation and nothing after"), but a buyer of a recycled name
  inherited sub-names nobody they knew of authorized.
- **Off chain, a malformed payload took the directory down.** The contract checks only
  that the payload hashes to the cell's commitment, never its shape, while both decoders
  throw on a bad one and `hydrateAll` rejected the whole `list()` on the first throw. One
  name registered with garbage records and Explore, `ownedNames` for anyone whose names
  sorted after it, and the resolver's snapshot were gone for everyone. **Fixed in the SDK**:
  such a name is skipped with a warning by `list()`, `liveCells()` and `ownedNames()`, and
  still fails loudly on its own through `getAccount` (an SDK test).

### Documentation defects corrected

Comments in this codebase are read as the specification, so a comment that promises more
than the code does is a defect: `account-cell-type` still said genesis was "gated to the
sequencer" in two places (it has been token-gated since H-1); `SPEC.md` §6 said the
action lives in `output_type` of witness 0 while §2.2 and the code say `input_type`; and
the doc comment for `require_owner` sat on `require_parent`.

### Checked and sound, so the next pass need not

The `covers`/`between` arithmetic in all three regimes (normal, wraparound, and the root
singleton where `between` degenerates to `id != lo`); every 20-versus-20 prefix compare
(`paid_to`, `signed_by`, `require_owner`, `reject_cell_lock_authority`, the referral
treasury check); the price cell's type-id creation and its step and cooldown rules;
`sale-lock` after F-5; that no transaction shape consumes an AccountCell without the
matching output (a burn is refused by arity on every action); and that every `QueryIter`
use fails closed. Still medium confidence, as before: reading witnesses by output index
through `Source::Input`, which the SDK's fixed output order keeps fail-closed.

## Pass 7, 2026-09-11 (a second fresh pass, the same day, after pass 6 shipped)

Run by a reviewer given only the scope, the harness and this file, forbidden to touch
contract source, and held to the same rule: reproduce before reporting. Three items, all
reproduced; none exploitable on the live namespace.

- **P7-1 (Info, fixed in source, deliberately NOT shipped as an upgrade).** R-5 pinned
  the root's length and empty label; `validate_genesis` still accepted any owner or
  manager on it, so a seeded root could have been a name somebody edits, transfers and
  names as a referral inviter. The live Pudge root was read from chain that day: owner
  and manager all zero, so nothing is affected, and genesis can never run again on this
  namespace (the token is spent), which is why the check is dead code here and only
  guards the next fresh deploy. Pinned by `genesis_rejects_a_root_with_an_owner`, with
  `genesis_creates_the_ownerless_root` as the control; the whole suite had been minting
  roots with owner A because the harness default said so, and `genesis_creates_root`
  now says `L::Null`.
- **P7-2 (Low, functional, fixed and shipped).** F-5 made the treasury's leg sum over
  every offer input, including one whose seller is present and is merely cancelling, so
  a cancellation beside a purchase demanded a fee on a name that was not sold. Fail
  closed, never built by the SDK, but a marketplace batching both would be refused.
  `owed_over_offers` now skips, for the treasury's leg only, an offer whose seller has an
  input in the transaction; every instance evaluates the same predicate over the same
  inputs, so they still agree on one figure and F-5 stays closed
  (`one_fee_cannot_settle_two_sellers` is the control).
  Test: `a_cancellation_beside_a_purchase_does_not_owe_the_treasury_twice`.
- **P7-3 (test quality).** `register_must_not_forge_a_name_at_the_root_id` described a
  v1 forgery the v3 layout cannot express (the id is the label's), died on error 24 and
  stayed green with `RootNotRecyclable` deleted from `validate_register`: a test that
  could not fail. Retired; the guard is pinned by two tests that reach it.

Upgraded to high confidence by reading `ckb-script` 0.119: a witness read by output
index through `Source::Input` resolves to a plain `witnesses.get(i)`, and a cell may be
both an input and a cell dep in one transaction. Both now have tests.

## Asked again 2026-09-14, and already answered: four surfaces re-checked

Recorded because "we think that is fine" and "somebody looked on this date" are different
things, and because three of these four were places picked as *probably unexamined* and
turned out to have been examined, with the reasoning written beside the code.

- **Someone else's image bytes, served from our origin** (the resolver). Handled, and the
  comment says how: the type comes from sniffing magic bytes and admits only PNG, JPEG,
  GIF and WebP, **never SVG**, which is a document that can carry script; `nosniff`; and a
  `default-src 'none'; sandbox` policy. The SVG we do serve is our own generated mark.
- **Someone else's HTML, published on chain and served by us** (the resolver). Handled harder:
  a separate domain, `sandbox; default-src 'none'` so the page has an opaque origin and no
  script at all, `nosniff`, `x-frame-options: DENY`, `referrer-policy: no-referrer`.
- **A forged Stripe webhook delivering a name for free.** Handled: HMAC-SHA256 over
  `timestamp.body`, a 300 second tolerance, a length check and a constant-time compare, and
  the signature is verified **before the body is parsed**. The route 404s outside live and
  test mode, and the fake-payment path needs both `MODE=fake` and a token header.
- **The registrar.** Not a surface: a pure library that computes a predecessor and builds
  cell bytes, holding no key and running nowhere. A wrong registrar produces a transaction
  the contract rejects.

**What that says about the remaining unknowns.** Everything found today was found by
changing the question rather than by running the suite: F-8 by asking where the money in a
successful transaction came from, F-9 by asking what happens when two of our contracts meet,
T-9 by asking who checks the thing that tells people where to pay. The places I could think
to look have now mostly been looked at, which is the point at which somebody who thinks
differently is worth more than another round from me.

## T-9 (**fixed 2026-09-14**): an answer from the resolver carried no evidence

The contracts get most of the attention because they are the part that looks like security.
This was found by asking a different question: **who checks the thing that tells people
where to send money?**

`/resolve` returned addresses, records, owner and expiry, and **no outpoint, no
transaction, no block, no hash, no signature**. the resolver notes (kept with the application, not in this repository) said any answer
could be checked against the chain without the resolver or any code of ours, and that was
true of the **name** and false of the **answer**: nothing in the reply said which cell it
came from, so checking it meant redoing the whole lookup, which is what a caller came here
to avoid. The honest description of the API was *trust us*.

**Our own app was never exposed**: it reads the chain in the browser and does not use this
route. The exposure was entirely to people integrating over HTTP, which is to say to
everybody the developers page is trying to attract.

Every answer now carries `proof`: the outpoint, the **whole** type script (the args are the
namespace, and the right code in the wrong namespace is a different protocol), the data
hash, the network, and a sentence saying what to do with them.

**Verified by following it**, against a public node, with nothing of ours deciding
anything: the cell is live, its code hash and namespace match, `blake2b(data)` matches
`dataHash`, and the label at the published offset reads `maria`. Five checks, one RPC call,
no trust.

## The class, completely: every "sum what is paid to L" check is safe only against itself

F-2, F-5 and F-9 are one mistake in three places, so after F-9 the codebase was searched
for the shape rather than waiting for a fourth. **Four** checks sum outputs paying a lock
and compare the total with what the script needs; one other reads a single output by index
and is immune by construction (the price floor).

| check | sums payments to | safe against |
|---|---|---|
| `account-cell-type::require_treasury` | the treasury | nothing outside itself (F-2, F-9) |
| `account-cell-type::paid_to`, the referral cut | the inviter's owner | itself only |
| `sale-lock::paid_to_pure(&seller)` | the seller | other offers in the same script (the F-5 fix) |
| `sale-lock::paid_to_pure(&TREASURY)` | the treasury | other offers in the same script |

**The rule:** a check of this shape is safe only against other instances of the **same
script**, because that is all it can see. Two *different* scripts needing payment to the
same lock in one transaction each read the whole sum and each is satisfied by it.

| pairing | status |
|---|---|
| treasury x treasury: a renewal or registration batched with a sale | **F-9, reproduced** |
| treasury x treasury: two namespaces | **F-2, reproduced 2026-09-14**, having been "untested because the harness cannot build it" since it was written |
| inviter x seller: a referred registration batched with a sale whose seller is the inviter | **reasoned, not built.** Identical shape, and the harness could now express it. Named here rather than left for somebody else to find, and not verified |
| seller x seller: two offers from one seller | F-5, fixed inside the sale lock |

**F-2's mitigation had already stopped being true when it was written.** It says the flaw
"is not exploitable today because only one namespace exists". A second script counting the
same treasury outputs does not have to be a second namespace, and `sale-lock` has been one
since 2026-09-05. The sentence was true about namespaces and false about the risk, which is
the more interesting kind of wrong: it was checked against the wrong noun.

**One fix covers all of them,** and it is one decision: some script has to demand the
**total** obligation in the transaction rather than its own share, which means reading the
other scripts' cells and computing what they owe. One-sided is enough, since the strictest
requirement binds. It couples contracts, which is why it is a decision and not a patch.

## F-9 (Medium, **fixed and live 2026-09-14**): one treasury payment answers two contracts

Found 2026-09-14 by asking the question an auditor would ask and this suite never had:
**what happens when two of our contracts run in the same transaction?**

Every test file deploys one contract. `account-cell-type` appears in two files, `sale-lock`
in two, `price-cell-type` in two, and **never two of them in one `Context`**. So the shape
that has already cost this project twice had a third home nobody had looked in: F-5 (one
sale fee answering two sellers) and F-2 (two namespaces sharing one treasury) were both a
total that two independent checks each read as satisfying them.

- `account-cell-type::require_treasury(need)` sums every pure output under the treasury
  lock and requires at least `need`.
- `sale-lock` calls `paid_to_pure(&TREASURY_LOCK_HASH)` and requires at least the sale fee.

Neither knows the other is running. Both count the same outputs.

**Reproduced against the real VM**, `contracts/tests/tests/cross_contract.rs`: a
transaction that renews `alice` (5,000 CKB owed) and completes a 10,000 CKB sale (100 CKB
owed), with **one** treasury output of 5,000 CKB, is accepted by both scripts. The protocol
is paid 5,000 where 5,100 is owed. The control in the same file, paying 5,100, also passes,
so the shape is constructible and the failure is specifically the double count.

**What it costs:** the smaller of the two fees, on any transaction that batches a sale with
a registration or a renewal. Not the larger: whichever fee is bigger covers both. A
purchase on its own is unaffected (the account action there is `transfer`, which owes
nothing), which is why nothing in production has lost anything.

**The fix, decided and shipped.** `account-cell-type` now reads the sale locks being spent
in the transaction, computes what they owe with `sale_fee` over the price in their own args,
and demands that **on top of** its own fee. One side is enough because the strictest
requirement binds, and this is the side that can do the arithmetic: the reverse would need
the sale lock to know an action, a term and a fee schedule. The referral cut got the same
treatment, since an inviter who is also a seller here would otherwise be paid once and
credited twice.

**The cancellation exemption is mirrored, not guessed.** `sale-lock` demands nothing for an
offer whose seller is an input, because that seller is cancelling rather than selling
(P7-2). Charging for those would refuse an honest batch, so the same predicate is applied.
It is duplicated logic and that is the real cost of this fix.

**The coupling, and why baking a number is safe here.** The account contract now carries
`SALE_LOCK_CODE_HASH`. A stale value fails **open**: it would stop recognising offers and
F-9 would be back silently. Two things hold it: the sale lock is upgraded **in place by
type id**, so its code hash does not move (three upgrades that day all printed
`sale.codeHash unchanged`), and an SDK test compares the baked value against
`deployment.json` on every run. Proven by ageing the constant by one character and watching
the test name the consequence.

**Both directions proven.** The reproduction passes now, the control (paying both fees)
still passes, and reverting the fix makes it fail again with the same message.

## F-10 (Low, open, found 2026-09-15 while checking an outside report)

the SDK's `codec` module's `pushBytes` already refuses a record `key`/`label`/`value` that
overflows its length prefix, and its comment says why: a 70,000-byte value used to be
written with a length of 4,464 and the rest of the record set decoded as garbage from
there on, so "refusing is the only honest option, since the wire format cannot express
it." That fix was never carried to the Rust side.

`cells-core::push_u8_len` and `push_u16_len` (`contracts/crates/cells-core/src/lib.rs`)
carry the identical comment, word for word in spirit ("the only honest answer is to
refuse"), but the code does not refuse: `out.push(b.len().min(u8::MAX as usize) as u8)`
clamps the length **byte** while `out.extend_from_slice(b)` still writes every byte of
`b`. The `debug_assert!` above each of those lines does not close it, because it is
compiled out of exactly the build that ships. No length check on a record's `key` or
`label` exists anywhere upstream of this call in the Rust crate.

**Measured, not argued.** A record with a 300-byte key, encoded in a release build,
comes out as 315 bytes whose first length byte reads 255. In a debug build the
`debug_assert!` fires instead and the process panics, which is why the gap is invisible
to `cargo test` run the ordinary way. The honest correction to the first description of
this finding: the payload does **not** decode into different records. `WitnessData::decode`
refuses it with `Error::Encoding`, with one record and with a second record behind it,
because the trailing bytes no longer line up. The control passes: a key of exactly 255
bytes round-trips.

**So the failure is closed, not open,** and that is the whole reason this is Low. Nobody
is paid the wrong amount and no other name is touched. What it costs is this: the
encoder writes a record set that its own decoder will never read, and by the time anyone
finds out, `blake2b(payload)` is already committed in the cell on chain. The records of
that one name are unreadable until its owner writes them again.

**Why it is not merely cosmetic.** The comment states a guarantee the code does not
provide, and in this repository comments are read as the specification. The two codecs
for one wire format disagree about what is writable.

**Why it is not urgent.** `push_u8_len`/`push_u16_len` are reached only through
`WitnessData::encode` and `build_account`, and a search of `contracts/contracts/` finds
no call to either: no on-chain script ever re-encodes, it only compares
`blake2b(the raw witness bytes)` against the stored commitment. The app builds its
witnesses with the TypeScript codec, which already refuses.

The Rust encoder does have callers outside the tests, and an earlier draft of this
finding was wrong to say it did not: the off-chain registrar (not in this repository) (`register.rs`, `fixtures.rs`,
`lib.rs`) and the off-chain indexer (not in this repository) all call `build_account`. Neither is deployed
(`the architecture notes (kept with the application, not in this repository)` says so in as many words), and more to the point the records they
build are hard-coded constants, a `address.60` key with a `demo` label and twenty bytes
of value. Nothing a caller supplies reaches a length prefix: the only user input on that
path is the label, which is the name itself and goes through `validate_label`. So the
overflow is unreachable from any input today, which is a stronger statement than the one
it replaces and rests on what the code does rather than on what has not been written yet.

**What was done, 2026-09-16: the comment, not the code.** The five lines above
`push_u8_len` promised a refusal the code does not make, and in this repository comments
are read as the specification, so a future Rust builder would have been written by
somebody trusting them. They now say what the code does and point here. The edit keeps
the line count, and that was measured rather than assumed: the four contracts were built
twice from the unchanged source (byte-identical, so the build is deterministic and the
comparison means something) and once after the edit, with every crate recompiling each
time, and all four hashes came out the same. a script (kept with the application, not in this repository), run afterwards,
reports MATCH for all four code cells. Nothing on chain moved.

**The code fix, deliberately not applied:** make `push_u8_len`/`push_u16_len` return
`Result` and refuse an oversized field, mirroring `pushBytes` exactly. It ripples to
`WitnessData::encode`, then `build_account`, then five call sites in the off-chain registrar (not in this repository)
and the off-chain indexer (not in this repository) and eleven in the contract tests. Done with the line count held it
should leave the binaries identical too, but every edit to `cells-core` is a chance to
make a mistake in the crate all four contracts link, and the only path this closes is one
nobody can reach. The trigger is **not** the registrar going live, because it never will:
`the architecture notes (kept with the application, not in this repository)` section 7 keeps it as a second implementation of the encoding and
nothing more, which is also the sharpest way to say what F-10 is, the one place where
that second implementation disagrees with the first. The trigger is the next change to
`cells-core` that is worth an upgrade on its own; this travels with it.

## Pass 8, 2026-09-14 (found by measuring a sale, not by reading the code)

One finding, high severity where it applies, **fixed and live on Pudge**. It was not
found by review: it was found by asking where the money went in a transaction that had
just been called a success.

### F-8 (High, **fixed, live on Pudge**): a buyer could pay the seller with the seller's own deposit

A listing parks a deposit in the offer cell, 160 CKB, so the listing is discoverable on
chain. `paid_to_pure` deliberately did not count that capacity, and the comment beside it
said whoever completes the sale keeps it, "which is roughly what the transaction costs
them". **The transaction costs 0.00002 CKB and the deposit is 160**, which is wrong by a
factor of eight million, and nothing enforced that the buyer bring anything at all: the
contract only required the *outputs* to the seller to reach the price.

So for any price below the deposit, a stranger could spend the offer cell, pay the seller
the asking price out of the seller's own money, and keep the rest along with the name.

**It was unreachable until the same day.** The floor on a listing was 630 CKB, four times
the deposit, so a taker always had to bring 470 of their own. Lowering the floor to what
a cell costs, which is what makes a cheap name sellable at all
([0025](decisions/0025-one-percent-on-a-sale.md)), opened it.

**Reproduced as a real sale before anything was changed**, which is how it was found:
`cartaoprova3695.cell` sold at 63 CKB in transaction
`0x4ea414a917e1b40364ce63e6404f088a5051714fe0fc21a9a86e4bd2864f0f1c`. The buyer's own
wallet contributed **0 CKB**. They received the name and 97 CKB; the seller "received" 63
having parked 160, and was 97 down.

**The fix**, in `owed_over_offers`: the offer cell's capacity is added to what the seller
is owed, so it comes back to them in the same transaction that sells the name. The buyer
therefore brings exactly the price, and the seller receives exactly the price. Eight
existing tests failed on the change and were right to, because every one of them encoded
the old split.

Pinned by `a_buyer_cannot_pay_the_seller_with_the_sellers_own_deposit`, with
`the_deposit_comes_back_to_the_seller_on_a_sale` as the control, and proven against the
deployed script by a proof script (kept with the application, not in this repository), which builds the attack by hand because
no honest client can express it: the chain refuses it at `Inputs[1].Lock`, and the honest
sale in the same run pays the seller 63 plus their 160 back.

**The lesson worth more than the fix:** a comment justified the design with a number
nobody had measured. Reading it, the design is reasonable. Measuring it, the compensation
is eight million times the cost it claimed to cover. Anywhere a comment says a value is
"roughly" something, the something is worth measuring once.

## What F-8 says about how we test (2026-09-14)

F-8 went through **171 contract tests and eight review passes** without being seen. It was
not found by a test. It was found by taking a transaction that had just been called a
success and asking where the money came from: the buyer's wallet had contributed nothing.

That is worth more than the fix, because it says what the suite was and was not doing.
Every one of the twenty-four sale tests described a sale somebody had already imagined,
and each asked *does this behave?*. None asked *is there any transaction in this space
that behaves wrongly?*, which is the only question an attacker asks. A list of examples
cannot answer it, however long the list.

**`contracts/tests/tests/sale_properties.rs`** now asks it for the sale lock. It
enumerates a grid, 225 combinations of nine prices against five payout offsets on each
leg, and asserts an **if and only if**: the lock accepts a purchase exactly when the
seller receives at least `price - fee + deposit` and the treasury at least `fee`.

**Proven to catch what the examples missed.** With the F-8 fix reverted and the contract
rebuilt, the property fails on **66 of the 225 combinations**, and the second property
names it in words: *"at price 61 the lock accepted a sale paying the seller 64 CKB, less
than the 100 CKB deposit they parked to list it"*. The first attempt at this control
reported the opposite, that the property did not catch it, because the rebuild had failed
and the test ran against the already-fixed binary. A control that is not itself checked is
not a control.

**What this does not cover, said plainly.** One property, on one lock. `register`,
`renew`, `transfer`, `edit` and `recycle` have capacity-conservation tests, but they are
hand-picked cases in the same style that missed F-8. The same treatment for the account
contract is the obvious next piece of work and is not done.

## What was built after F-8, and what each piece is proven to catch (2026-09-14)

Three gaps were named in the pass above. All three are closed, and each closure was
checked by breaking the thing it guards and watching it fail.

### Properties over the account contract, not examples

**Complete as of 2026-09-14.** Eight properties, and every guard they cover was disabled
in turn to watch the right one fail:

| guard broken | what failed | what stayed green |
|---|---|---|
| `capacity_not_reduced` disabled | both capacity properties, naming renew, edit_records, transfer and recycle's neighbour | everything else |
| `require_treasury` weakened to half | the fee property, catching the one-shannon case | everything else |
| `GRACE_SECONDS` ignored | the recycle property, and only it | six others |
| commit maturity halved | the commit-reveal property, and only it | six others |
| `between` admitting its low endpoint | the ring property, naming `between(0, 1, 0)` and 32,640 disagreements, plus five downstream | recycle and the endpoints |

The last row is the one worth reading twice: breaking the ring breaks almost everything,
because almost everything depends on it, and the ring property is what says *which*
function and *which* case rather than leaving six red lines and a guess.

**Two of the properties were wrong before the contract was.** One asserted that a cell's
id must equal its label's hash; it failed in both directions, and the reason is that
**there is no stored id** (decision 0015). It is derived from the label every time, so
there is no field to forge and no check to test: the layout is a stronger guarantee than a
check would be. The other wrote out the ring's definition independently and got the
degenerate case wrong, reporting 65,536 disagreements with a contract that was right: a
ring of one name points at itself, so its range is the whole ring, and walking back to
where you started is a full lap rather than zero steps. **An independent definition earns
its keep by being wrong in public**, which is the only way to find out that the reading in
somebody's head was not the reading in the code.

#### The first two, and what each is for


`property_no_action_may_shrink_the_name_cell`, `property_recycle_never_touches_the_neighbour`
and `property_the_fee_must_be_paid_in_full_or_not_at_all` sweep a grid around every
capacity and every fee, and assert an if-and-only-if: the contract accepts exactly when
the rule says it should.

**Proven sensitive, and proven independent**, which matters more than proven green:

| what was broken | what failed | what stayed green |
|---|---|---|
| `capacity_not_reduced` disabled | both capacity properties, naming renew, edit_records, transfer and recycle's neighbour | the fee property |
| `require_treasury` weakened to half | the fee property, catching even the one-shannon short case | both capacity properties |

Each property catches its own guard and ignores the other, so a pass means something
specific rather than meaning the suite ran.

### A fuzz over everything that reads a stranger's bytes

`fuzz_parsers.rs`: 105,000 inputs from a seeded generator through `AccountData::parse`,
`parse_price_factor` and `validate_label`. Noise, single-bit mutations of valid records,
truncations, and appended rubbish. It asserts nothing panics, that whatever the writer
wrote the reader reads back exactly, and that every prefix shorter than the 98 byte header
is refused rather than interpreted.

Not cargo-fuzz, deliberately: that needs nightly and a corpus on somebody's machine, and a
corpus that is not in the repository is a corpus that is not run. This is weaker at finding
deep paths and stronger at being run, which for a suite nobody is paid to babysit is the
better trade. A failure reproduces from the seed in the message.

**Proven to catch:** the length check in `parse` was weakened by eight bytes, and two of
the five failed at once, with *"90 bytes is shorter than the 98 byte header and must be
refused, not interpreted"*.

### Somebody now reads the wallet fingerprint

The worst of the three, and it was worse than the pass above admitted. The owner's wallet lock is code we will not audit, and what we can do is notice. The resolver computes a fingerprint over that lock's code
cells every few minutes and publishes it at `/api/health`.

**Nothing read it.** The alerting service on the server was searched line by line on
2026-09-14 and mentions neither the wallet watch nor Cells at all. The state was
computed, published, and looked at by nobody. "We can notice" was half true: we could have
noticed, and nothing would have.

a proof script (kept with the application, not in this repository), installed as `cells-sentinel.timer`, reads it every thirty
minutes along with the quantum lock, the price cell, the shop and the app, and emails
through the same channel the machine already uses. It reports differences and does not
judge them.

**Both halves proven, because a watcher nobody has seen fire is a watcher nobody knows is
connected:**

- **It sees a change.** Fed a doctored `/api/health` from a local stub, it reported
  *"joyid testnet: A IMPRESSAO DIGITAL MUDOU"* with both fingerprints and exited 1.
- **The alert leaves the machine.** `--test` sent a real email through Resend and the API
  accepted it.

Both were needed. The first without the second is a watcher talking to itself.

## What a name depends on, and who has looked at it (2026-09-12)

Every pass above is about code we wrote. A name at rest also obeys code we did not write,
and that list had never been written down, so the honest state of each is below.

| Script | What it holds | Reviewed by us | Audited by anyone | Watched |
|---|---|---|---|---|
| `account-cell-type`, `account-lock`, `sale-lock`, `price-cell-type` | the names, the sales, the price | yes, the passes above | **no** (dropped as a mainnet gate, decision [0010](decisions/0010-shipping-without-an-external-audit.md)) | the watchtower, by type args and outpoint |
| SPHINCS+ quantum lock | a quantum-owned name | no, we reproduced the bytes instead | **yes**, ScaleBit, December 2025 | the resolver, `lock.ok`, and the sentinela every 5 min |
| the owner's wallet lock | the owner's wallet, and so the name | **no**, outside our scope | outside our scope | the resolver fingerprints it, since 2026-09-12 |
| CKBFS v3 | the copy of the app on chain | **no** | not that we have seen | no, and pinned by data hash so it cannot change under us |
| CKB system scripts (secp256k1, multisig, type id) | everything | no | in the genesis block and immutable | not worth watching |

Two things this table is meant to stop being forgotten:

**The wallet lock an owner chooses is not a dependency of the protocol.** The app mounts the
wallet connector with no filter, so a name can be owned by a plain CKB key, by an EVM or
Bitcoin key through Omnilock, or by the post-quantum lock. For the most common wallet lock the
resolver fingerprints the code cells, and since 2026-09-14 something reads that fingerprint
every half hour and mails on a change.

**CKBFS v3 was missing from this document entirely** until today, which is worse than
being listed as unreviewed: an absent row reads as nothing to think about. The exposure is
genuinely small, since we pin it by data hash and losing it loses the on-chain copy of the
app rather than anybody's name, but small is a conclusion somebody should reach on
purpose.

## Pass 9, 2026-09-17 (asked as a thief would ask: drain, destroy, hold to ransom)

Run four days before mainnet opens, against the question in its plainest form: can funds
be drained from this, can a name be blocked or destroyed, can a name be held hostage. Read
in full that day: the four contracts, `cells-core`, the shop, the resolver's write routes
and `/primary`, the price keeper, the SDK's `buy` and `transfer`. The suite was run the
same day (181 tests green, `make test`), `/verify` answered `verified: true` for all four
code cells, and nothing new was found in the contracts. What was found sits beside them.

### The three questions, answered

**Drained.** Not through the contracts: every path that moves a name's capacity is pinned
(`capacity_not_reduced` on all five actions, the predecessor byte-for-byte on register, a
burn refused by arity on every action), every payment check counts pure outputs only, and
the sale lock has no instant at which either side holds both the name and the money. What
can drain is a key: the upgrade key (T-1, every name; accepted and said in TRUST.md), the
shop's hot key (bounded by its float, its reserve and the daily cap, 25 sales or 150,000
CKB), the price key (bounded to a sixteenth every six hours inside the band, so revenue,
slowly and visibly, never funds), the treasury key (revenue, and free registrations). And
users' wallets can be drained by a front end that is not ours: the build comes from GitHub
and runs on the server, so the GitHub account and the server are the two places a malicious build
would come from. Nothing in the app loads a third-party script at runtime.

**Blocked or destroyed.** No transaction consumes a name without its matching output; no
lock but the account-lock is accepted (48); a name's records can be made unreadable only by
its own owner (F-10). A stranger can race an owner's transaction by spending the same cell
through a permissionless renew or a registration under it, and each attempt costs the
attacker a full year's fee and gives the victim a year, so it is a gift, not a lever. The
resolver as a service can be slowed (per-IP limits, 96 KB seals, five reports an hour), and
every integrator is told to read a failure as "no name", which degrades and does not break.

**Held to ransom.** Three shapes exist, all by design and all documented: a name that lapses
is anybody's thirty days later (the drop-catch, decision 0009; the reminder and `/expiring`
are the mitigation); a sub-name cannot be evicted by its parent and survives the parent's
sale (0008); a delegated manager can redirect payments in the records until the owner
notices, and the owner can revoke at any moment (0006). None can be reached by a stranger
against a name whose owner renews.

### P9-1 (Low, **fixed**): the SDK sold a lapsed listing

`buy()` took `getLive` to mean "live" when it meant "the cell exists". The app's market
has said "expired" and offered no button since 2026-09-05; a client built on the SDK, which
the developers page invites, got no such word and could pay for a name that anybody could
recycle in the next block. `nameState` in the SDK's `codec` module now gives `live`, `grace` or `free`
with the chain's and the resolver's own boundaries (`name-state.test.ts` pins both), and
`buy()` refuses a free name outright and a name in grace unless told `allowLapsed`.

### P9-2 (Medium, operational, **fixed and installed**): nothing remembered the names we must keep

RESERVED.md and the mainnet runbook (kept with the application, not in this repository) 1.4 both say the safety tier (`admin`, `support`, `claim`) is
registered by us so that nobody can run a phishing kit on our rails, that renewal is free
from the treasury key, and that "somebody has to remember". Nothing did. The sentinel
watched JoyID, the quantum lock, the price cell, the shop and the app, and not one name.
Thirty days after a forgotten renewal, `support.cell` would have been a stranger's,
publishing a payout address at `support@cellula.id`.

a script (kept with the application, not in this repository) now reads a watch list on the server (label, optional owner id) and
raises a finding when a name there is not registered, has changed owner, or is inside
sixty days of lapsing, which with the grace period is ninety days before anybody can take
it. Proven both ways on 2026-09-17: a missing name and a wrong owner each fired, a correct
line stayed quiet, and a name ten days from expiry fired through the same function. The
mainnet reserved list goes into that file in the same step that registers the names
(the mainnet runbook (kept with the application, not in this repository), section 3).

### P9-3 (Medium, **fixed, live on Pudge**): a sub-name could buy its own future

The rule was set the same evening, on reading the hostage answer above: a sub-name never
outlives its parent, and if the parent is not renewed by the same wallet, the sub-name
expires. The first half was already on chain (`ParentOutlived`, at register and at renew).
The second was not, and pass 6 had written the gap down as a design note rather than a
finding: `renew` was permissionless for a child exactly as for a plain name, so the holder
of `shop.brand` could renew `brand` for its owner (anyone may), then `shop.brand` for
themselves, and keep the child alive through a sale of the parent, or through its lapse,
recycle and fresh registration by a stranger. The new owner of `brand` could not evict it.

**Reproduced first.** `subname_renew_by_nobody_is_refused` and
`subname_renew_by_the_child_owner_alone_is_refused` both reported "expected a failure, it
passed" against the contract as deployed; `subname_renew_by_the_parent_owner_passes`
already passed and is the control. **The fix** is one line in `validate_renew`'s sub-name
block: `require_owner(p.owner_lock_hash())`, the same proof creation already asks for. A
plain name's renewal stays permissionless. Both refusals now fail with `Unauthorized`
(29), the control still passes, and `renew_extends_ok` (a plain name, nobody signing) is
unchanged.

What it changes for a person: whoever holds `shop.brand` and not `brand` asks `brand`'s
owner to renew it, and the SDK takes that owner as `parentSigner` exactly as `register`
does; the app's Renew panel says so before the button. Decision 0008 is rewritten, and its
2026-09-11 note is kept there as superseded.

**Shipped and proven on Pudge the same night.** In-place upgrade
`0x57ed78e4…` (the test-network deployment log (kept with the application, not in this repository)). Then, against the live contract, the pre-fix SDK was used to
build the old permissionless shape for `shop.p232mn2a.cell` paid by a key that owns
neither it nor its parent: the node refused it, `Inputs[0].Type` error code 29. The same
renewal signed by the parent's owner landed as
`0x66fb2861ee41fde9a20f1e95692790b9306b84140413158f2b7f6e61759b3af2`, and the name reads
back 365 days longer. Both halves, on the chain that matters, before this was written.

### Noted, not changed

- No `Content-Security-Policy` on the app origin (`x-frame-options`, `nosniff` and HSTS
  are set). React escapes what it renders and the app loads no third-party script, so this
  is depth rather than a hole; the stranger-written HTML already lives on its own host under
  `sandbox`.
- `/primary` is forward-verified (the reverse cell must sit under the address, and the
  name's owner or manager must be that address), so it cannot be spoofed by writing an
  address into a record. `/reverse` is record-based on purpose and says so; an integrator
  who confuses the two is reading a claim, not a proof.

## Model & trust assumptions

- The AccountCell **lock is always-success** (`account-lock`); the **type script
  `account-cell-type` is the sole guardian**. This is safe *only* if the type
  script is exhaustive, a CKB type script runs on inputs *and* outputs, so it
  mediates every consumption of an AccountCell.
- Uniqueness of names rests on the **circular linked list** (`cells-core`
  `covers`/`between`) plus a **single root**. If a second root can exist, the
  uniqueness guarantee fails (see **H-1**).
- The owner identity is a **lock hash** in authenticated `data`; owner actions
  require co-spending a cell under that lock.

## Per-action summary (what is enforced)

The contract's own actions. For the **whole** product, including the parts no contract can
enforce (the card path, the resolver, the disputes policy), see the product rules (kept with the application, not in this repository),
which carries the level each rule is actually enforced at.

| Action | Enforced |
|---|---|
| integrity (all outputs) | label charset/length, `id == blake2b(label)`, `witness_hash == blake2b(witness)`; root exempt |
| `register` | new id strictly inside predecessor range; exact relink; predecessor preserved byte-for-byte except `next` incl. capacity≥ and lock; refundable rent (`price_floor`); non-null owner (L-1); **term of 1 to 10 whole years** from the CommitCell's block timestamp (subsumes L-2); **fee paid to the treasury lock** (`registration_fee`, per year, by label length); **commit-reveal** (spends a matured CommitCell matching `blake2b(ns‖label‖owner‖secret)`); permissionless |
| `edit_records` | 1-in-1-out; id/next/account/expiry/owner/**manager**/version/lock fixed; witness may change; **owner OR manager co-sign** |
| `edit_manager` | 1-in-1-out; only `manager_lock_hash` changes (output is v2); records/owner/everything else fixed; **owner co-sign** |
| `transfer` | 1-in-1-out; id/next/account/expiry/lock fixed; `owner_lock_hash` may change to a non-null value; **manager reset to the new owner**; **current-owner co-sign** |
| `renew` | 1-in-1-out; only `expired_at` grows, by 1 to 10 whole years from the old expiry; **the same per-year fee paid to the treasury**; a sub-name may not be renewed past its parent (parent supplied as a cell dep) **and needs the parent owner's co-sign** (2026-09-17); owner/lock/witness fixed; permissionless for a plain name |
| `recycle` | 2-in-1-out; predecessor preserved; target spliced out; expiry proven via absolute-timestamp `since` |
| `genesis` | single root (id==next==0); must consume the one-time genesis-token |

These were checked against multi-cell/mislabelled-action/wrong-count abuse: each
validator pins exact input/output counts, so actions cannot be batched or confused.

## Findings

| ID | Severity | Status | Title |
|---|---|---|---|
| **H-1** | **High** | **Fixed** | ConfigCell was not a global singleton → genesis gate forgeable → duplicate names |
| M-1 | Medium | **Resolved (by design)** | `recycle` pays the expired name's deposit to the recycler, keeper bounty (decision 0005) |
| M-2 | Medium | **Fixed** | `recycle` relied on inductive list integrity (no explicit `x.id == p.next`) |
| L-1 | Low | **Fixed, both halves** | Owner could brick/weaken a name via `owner_lock_hash` = zero (fixed 2026-06-11) **or = the account-lock hash** (fixed 2026-09-04, `OwnerIsCellLock`). The second was the worse one: `account-lock` is always-success and every AccountCell carries it, so `require_owner` was satisfied by the predecessor `register` spends or by the cell being edited, making the name editable, transferable and sub-nameable by anyone. Now refused at `register`, `transfer` and `edit_manager` (the manager had no constraint at all). |
| L-2 | Low | **Fixed** | No on-chain future-expiry / minimum term (an already-expired name can be registered) |
| I-1 | Info | - | Always-success lock ⇒ total reliance on the type script (by design) |

## Adversarial review, 2026-09-04 (decision 0010)

Four independent passes over the in-scope code, each required to produce a buildable
transaction rather than a concern. Five holes, all closed the same day, all with tests
that were **run against the guard disabled** to prove the test can fail. The suite went
from 55 to 62 VM tests.

| # | Severity | What | Closed by |
|---|---|---|---|
| **R-1** | **Critical** | **Name uniqueness could be broken.** Anyone could recycle the root sentinel: `validate_recycle` never excluded it, `covers` admits it as the upper endpoint of the last node's range, and it was created with `expired_at = 0` so its expiry proof was free. With the root gone the ring covers id zero, and the id-derivation exemption was written as "any cell whose id is zero" rather than "the root", so a register could then mint a cell with id zero and **any label, including one already registered**. Two live cells, same name. Found independently by three of the four reviewers. | `RootNotRecyclable` (46) in `validate_recycle` and `validate_register`; the integrity exemption narrowed to `id == ROOT_ID && account().is_empty()` |
| **R-2** | **Critical** | **The reveal was front-runnable.** `require_commit` matched a CommitCell by data alone and never checked who held it. A commitment is the cell's entire data, so it is public the moment the commit confirms, a full `MIN_DELAY` before the reveal. Anyone could copy those 32 bytes into a cell of their own, mature it on the same clock, read the secret out of the victim's broadcast reveal and land the registration first. | `CommitNotOwned` (47): the matching input's lock hash must equal the name's `owner_lock_hash` |
| **R-3** | **High** | **A manager could be installed at registration.** The commitment does not cover the manager and `register` never constrained it, while `transfer` always did. Chained onto R-2 that is permanent control of a name's records, on a name that reads as its owner's. | `register` requires `manager == owner`; delegation is `edit_manager`, which the owner signs |
| **R-4** | **High** | **Capacity was unguarded on every action except register.** `predecessor_preserved` checked it; `recycle`, `renew`, `edit_records`, `edit_manager` and `transfer` did not. Three of those are permissionless, so a stranger could keep a name intact and take its refundable rent. | `capacity_not_reduced` at all five call sites |
| **R-5** | **Medium** | **Genesis never pinned the root's shape.** No length or empty-label check, so a seeded root could have carried a label or a manager field, which is the premise the v1/v2 discriminator rests on. | `validate_genesis` requires `data.len() == DATA_HEADER_LEN` and an empty label |

**Two test-quality findings that mattered more than any single bug.** The property test
cited as evidence for the uniqueness invariant excludes the root from recycling and id
zero from registration, i.e. it hard-codes the two assumptions the contract failed to
enforce; 8 000 random operations could never have found R-1. And the harness computed
the commitment from the **v1** label offset, so a v2 registration could not be expressed
in it at all, which is why nothing ever tested a manager at registration (R-3). Both are
fixed.

Proved on the live deployment by a proof script (kept with the application, not in this repository): recycling the real
root now returns 46, while the same transaction shape against an ordinary live name
returns 28 (NotExpired), which shows the transaction is well formed and that 46 was the
root rule rather than a build error.

> **H-1, M-2 and pricing are live** on the genesis-token deploy `0x08d4b89d…`
> (the test-network deployment log (kept with the application, not in this repository)). See **Residual trust assumptions** below for the open governance question.

### H-1 (High): ConfigCell is not a global singleton

`validate_genesis` finds the ConfigCell among cell deps by **type hash ==
`config_type_hash`** (this script's args), then requires consuming the seed named
in its `data[32..64]`. But `config_type_hash` is the hash of *any*
`config-cell-type` instance with empty args, and `config-cell-type` only enforces
"≤1 ConfigCell **per tx**", **not global uniqueness**. So an attacker can:

1. create their own ConfigCell (same type hash) whose `data[32..64]` names a seed
   **they** control;
2. create that seed (a type-id cell they own);
3. run a genesis tx that deps their ConfigCell and consumes their seed →
   `validate_genesis` passes → **a second root is created**.

Two roots ⇒ two circular lists sharing the same `account-cell-type` args, so the
same label can be registered in each (same id, two cells). **The core uniqueness
guarantee is broken.** (The earlier sequencer gate had the same hole, a forged
ConfigCell could carry an attacker sequencer hash.)

**Fixed** (merged design): there is no ConfigCell at all. Genesis must **consume a
one-time genesis-token**, an input whose type-script hash equals
`account-cell-type`'s args (the *namespace id*). The token is a **type-id cell**:
globally unique and unrecreatable (its type hash is bound to a now-spent outpoint),
so it cannot be forged and is spendable exactly once. `config-cell-type` was dropped
(it only enforced one-per-tx, which was the whole bug). VM tests:
`genesis_creates_root` passes only with the token consumed; `genesis_rejects_without_token`
rejects without it. **Live on Pudge** (deploy `0x08d4b89d…`): genesis consumed the
one-time token, so a second root is now impossible (the test-network deployment log (kept with the application, not in this repository)).

### M-1 (Medium, **Resolved by design**): recycle deposit goes to the recycler

On `recycle`, the expired name's deposit becomes the recycler's change. **Resolved as
the keeper/cleanup bounty** (decision 0005): it is the incentive for the
permissionless cleanup, and, decisively, the type script *cannot* refund the owner
anyway (it stores only the owner's lock **hash**, not the lock **script**, so it
cannot construct a refund output). Recycle is only possible *after* expiry; an owner
keeps their deposit by renewing before then.

### M-2 (Medium, **Fixed**): recycle correctness relies on list integrity

`validate_recycle` checked `covers(p.id, p.next, x.id)` and `p'.next == x.next` but
not explicitly `x.id == p.next` (that x is p's *immediate* successor). **Fixed:**
recycle now asserts `x.id == p.next` directly, so it stays correct even against a
list corrupted by another bug.

### L-1 (Low, **Fixed: null owner**): owner misconfiguration

If `owner_lock_hash` is set to zero the name can never be edited/transferred; if set
to the account-lock hash (always-success) it becomes editable by anyone. **Fixed
(null case):** `reject_null_owner` now rejects an all-zero `owner_lock_hash` on both
`register` (new cell) and `transfer` (new owner), `Error::NullOwner`, live on
Pudge. The account-lock-hash case is left open (the type script does not carry the
account-lock's hash; a client-side warning is the pragmatic guard, and it is purely
self-inflicted). The root's zero owner is set at genesis, never via register/transfer,
so it is unaffected.

### L-2 (Low, **Fixed**): no on-chain future-expiry / term

`register` did not bound `expired_at`. **Fixed** (decision 0006): register now
requires `expired_at ≥ now + MIN_REGISTRATION_TERM` (1 day), with "now" read from the
spent CommitCell's block header (`header_dep`). The CommitCell is recent, so the clock
is sound and needs no new trusted input; cheating only self-harms (you would register
an immediately-recyclable name), so the bound is sufficient. Live on Pudge.

### I-1 (Info): always-success lock

By design, all safety lives in the type script. This is sound *given* the type
script is exhaustive (and CKB runs type scripts on inputs+outputs), but it raises
the cost of any type-script bug to "all names". Defense-in-depth (a thin owner lock)
is a possible future hardening.

## Residual trust assumptions

Even with H-1 fixed, the protocol is **not yet fully trustless**. In rough order of
importance:

- **T-1 (High), the upgrade key.** The code cells are deployed by **type-id, so
  they are upgradeable by whoever holds their lock** (a single deployer key; on
  2026-09-11 it was moved to a 2-of-3 system multisig, proven both ways, and moved back
  the same day, decision 0022: with every key on one machine it was one key with extra
  steps, and while fixes land daily the honest description is "single key". The move to
  real holders is rehearsed and one transaction away when wanted). That holder can replace the contract binary and **rewrite every rule**, 
  steal names, mint duplicates, drain capacity. This is the single biggest trust
  point, and it is a *direct consequence of the type-id upgradeability* added for
  in-place fixes. To be trustless the upgrade capability must be removed or
  decentralised: **burn it** (lock the code cells under a provably-unspendable lock
  → immutable, no more upgrades), or put it behind a **governance multisig** and/or
  a **timelock**. Until then, users trust the deployer not to push a malicious
  upgrade. *This is the recommended next decision.*
- **T-2 (Medium), genesis bootstrap.** The deployer performs genesis once (consumes
  the genesis-token). They could bootstrap a malformed/seeded genesis, but it is
  **verifiable**: anyone can inspect the genesis tx (root `id==next==0`, no
  pre-registered names). After genesis, registration is permissionless.
- **T-3 (Low), id truncation.** `id = blake2b(label)[..20]` is 160-bit. A collision
  (two labels → same id) costs ~2^80 and could only *block* a specific name
  (griefing), not redirect one. Acceptable, noted.
- **T-4 (Low), record data availability.** Records live in the **witness**, not the
  cell; resolution reads them from the cell's creating tx. CKB retains committed tx
  witnesses, so this is the standard CKB DA assumption, but an indexer must be able
  to fetch the origin tx.
- **T-5 (Info), the read gateway is centralised but not trusted.** the resolver
  is a convenience cache; every answer is verifiable against chain (the SDK reads
  directly), so a dishonest gateway can be detected, not believed.
- **T-6 (Info), the owner's algorithm.** Nothing in the contract fixes a signature
  scheme: an owner is any lock, proven by an input under it, and CKB's SPHINCS+ lock is
  accepted today (decision [0016](decisions/0016-post-quantum-owner.md), proven on Pudge
  2026-09-10: a name went to a quantum owner, was delegated back to an ordinary key and
  returned, through the unchanged SDK). What stays elliptic-curve is ours: the upgrade key
  and the compiled-in treasury lock, both to move when T-1 is applied.
- **Base layer:** CKB consensus and the system scripts (TypeId, and secp256k1 where a
  user chooses it) are trusted, as for any CKB app.

(Front-running on `register`, naive first-tx-wins, is an *adversarial vector*, not
a trust assumption. **Now mitigated:** commit-reveal is implemented and live
(decision 0004), a register must spend a CommitCell that is ≥ `MIN_DELAY` old
(relative-timestamp `since`) and matches `blake2b(ns‖label‖owner‖secret)`, so a
mempool watcher can neither copy the label nor reuse the victim's commitment.)

> Written in June 2026. The external audit no longer gates mainnet ([0010](decisions/0010-shipping-without-an-external-audit.md)); the rest stands as the list it was.

## Priorities

1. **External audit**, commission a third-party review. The functional findings are
   now closed (H-1, M-2, pricing, commit-reveal, M-1, L-1) and the list invariant is
   property-tested; the protocol is ready for an external pass.
2. **T-1**, the upgrade-key policy (burn / governance / timelock). The biggest
   remaining trust point, but it must be applied **last** (locking the contract
   blocks any further upgrade), i.e. after the audit and any final fixes.
3. **L-2** (on-chain future-expiry) + the manager/owner split, deliberate Phase-3
   features, the latter on a clean v2 data layout.

*(H-1, M-2, pricing, commit-reveal and L-1 are live on Pudge; M-1 resolved by
design, see the test-network deployment log (kept with the application, not in this repository) and decisions 0004 / 0005.)*

> Written in June 2026. The external audit no longer gates mainnet ([0010](decisions/0010-shipping-without-an-external-audit.md)); the rest stands as the list it was.

## External audit readiness

An external audit must precede any mainnet/value deployment. This internal review is
the starting scope; an auditor should focus on:

- **In scope:** `crates/cells-core` (layout + linked-list math `covers`/`between` +
  `validate_label` + `price_floor`), `contracts/account-cell-type` (all six actions
  + genesis-token), `contracts/account-lock` (always-success, confirm the type
  script is exhaustive given it), and the deploy/genesis flow (type-id derivation,
  genesis-token consumption).
- **Focus areas:** the linked-list uniqueness invariant under adversarial insert/
  recycle sequences (**now property/fuzz-tested**, `cells-core`
  `linkedlist_invariant_under_random_ops`, 8 000 random ops asserting the partition);
  the genesis-token unforgeability; predecessor-preservation in `register`; the
  commit-reveal binding + `since` check; owner co-sign in `edit`/`transfer`; the
  price-floor and capacity checks.
- **Known/accepted before audit:** T-1 upgrade-key policy (decision 0003, applied
  last), M-1 recycle deposit = keeper bounty (decision 0005), L-1 account-lock-hash
  case (client-side), L-2 no on-chain future-expiry (#2b), manager/owner split
  deferred to a clean v2 layout.
- **Recommended additions for the auditor's benefit:** property-based tests over the
  list invariants, and `ckb-debugger` cycle profiles for each action.

