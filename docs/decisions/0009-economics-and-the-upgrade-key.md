# 0009: Term, fees, and keeping the upgrade key

Status: **Live on Pudge since 2026-09-04** (upgrade `0x8500ea2e…`). Steps 1 to 3
below are implemented and proved on-chain; step 4 (auctions, sub-name issuance) is
not built. It changed the contract, which is why it landed *before* the external
audit rather than after: otherwise the audit would have been paid for twice.

Supersedes the "burn is strongest" leaning in decision
[0003](0003-upgradeability-and-governance.md). The key is kept.

## What was broken, and is not any more

Each of the three below is now enforced on-chain; the description is kept because it
is the reason the design is what it is.

The protocol took nothing, and could not, because the parts that would carry a fee did
not exist:

- **There was no term.** `register` defaulted `expired_at` to `4_000_000_000`, the
  year 2096, and the contract enforced only a one-day minimum. A name was registered
  once and effectively forever.
- **Renewal was free.** `validate_renew` checked that the new expiry was greater than
  the old one and nothing else, so anyone could renew any name for a network fee.
- **`price_floor` is not revenue.** It is refundable state rent that sits in the
  registrant's own cell. That part has not changed, and it is why the fee had to be a
  separate output rather than a bigger deposit.

So nothing expired, there was nothing to renew, nothing could be auctioned and nothing
was earned. **The order below was a dependency chain, not a wish list**, which is why
the term landed first even though it earns nothing by itself.

## 1. A real term

`register` takes a term in years (default 1, maximum 10) and computes `expired_at`
from the CommitCell's block header, which is already read for the L-2 future-expiry
check. `renew` extends by whole years under the same maximum.

This alone earns nothing. It is what makes everything below possible.

## 2. A registration fee

`validate_register` gains one check beside the price floor: an output to the treasury
lock holding at least `fee(label_length, years)`. The fee is **on top of** the
refundable rent, and unlike the rent it does not come back.

## 3. Paid renewal

Same check in `validate_renew`. This is the recurring revenue, and the only line that
compounds. Renewal stays permissionless: anyone may renew anyone's name, they just
have to pay.

## 4. Then, and only then

Expired-name auctions and a sub-name issuance fee. Both need names that actually
expire, which is step 1.

## Pricing: CKB, adjusted by governance, bounded in the contract

**Rejected: pegging to USD via an oracle.** A CKB type script can only read what is in
the transaction, so a live price must arrive as a cell dep. That buys three problems:
whoever updates the cell sets our prices; a stale cell prices names wrongly; and a
**consumed** cell makes every registration transaction invalid, bricking registration
on a dependency we do not control. It also destroys the property this protocol is
otherwise able to claim, that nothing needs to be kept running.

The ecosystem does not offer a way out. The CKB-native oracles that exist
(`ckb-band-oracle`, `ckb-open-oracle`, `ckb-oracle-bridge`) are single-author
prototypes last touched in 2020 and 2023; DIA publishes a CKB price but off-chain,
which a script cannot read. Pegging to USD means building and operating the oracle
ourselves, forever.

**Chosen:** the fee is a CKB amount, a constant in the contract, changeable only by an
upgrade.

The honest cost: if CKB moves an order of magnitude, the fee is wrong until an upgrade
fixes it. We accept a slow, visible correction over a fast, fragile automatic one.

**Reopened and re-affirmed in [0014](0014-repricing-without-an-oracle.md)**, which prices
that cost, records why a "bounded keeper" is open decision 2 in disguise, and designs the
cheap version (the schedule stays as a ceiling; a price cell may only discount from it) for
whenever it is worth building.

### Correction: the clamp does not bind an upgrade, and cannot yet

An earlier revision of this file claimed the contract would clamp the fee "so no future
upgrade (or compromised key) can set registration to zero or to an absurd number".
**That was wrong, and it is worth saying why rather than quietly deleting it.** The
clamp would live in the same code the upgrade replaces. Whoever can publish new code can
publish new bounds with it, so a bound written beside the number it guards guards
nothing against the only party able to change the number.

A clamp only binds if it lives somewhere the upgrade cannot reach. On CKB that means the
**code cell's own lock**: a bespoke lock that refuses a replacement whose constants fall
outside the band. Which is the same bespoke lock that open decision 2 contemplates for
the upgrade delay.

**So open decisions 2 and 3 are one decision, not two.** An enforced delay and an
enforced price band are the same mechanism (restrict what an upgrade may do), the same
new security-critical code, and the same audit scope. Either both are worth that lock or
neither is.

Until then the bounds are what they honestly are: **constants asserted in the test suite
and visible in review**, plus `cells-watchtower` firing on any upgrade at all. That is a
tripwire, not a lock. Public material must not describe it as a guarantee.

## The upgrade key is kept, and said out loud

T-1 is **not** burned. The reasoning has flipped since 0003: a fee schedule fixed in
CKB and an unburnable contract cannot coexist, and a protocol meant to last decades
needs a way to fix what an audit finds after the audit.

What this costs, stated plainly because it must never be hidden: **Cells cannot claim
that nobody controls it.** The accurate sentence is "the contract can be changed by the
holders of the upgrade key, here is who they are and here is the delay". Any public
material that says otherwise is false, and this file exists partly so nobody writes it
by accident.

### Watching comes first, and it is running

A timelock is only worth what the watching is worth. A seven-day delay nobody is
looking at is a seven-day delay nobody uses: the thief waits it out and publishes.
So the order is **detection first, enforcement when there is something to protect**.

Detection is live as of 2026-09-04, and cost no new audited code, because it adds
nothing to the contract. `ckb-monitor` runs on the server as `cells-watchtower.service`
(enabled at boot, restarts on failure), watching:

| watch | fires when |
|---|---|
| `cells-code-upgrade` | any tx carrying the `account-cell-type` code cell's type-id, i.e. the code is being replaced |
| `cells-code-destroyed` | that exact cell is **spent**, whatever happens next |
| `cells-lock-upgrade` | the same for `account-lock` |
| `cells-upgrade-wallet` | funds arriving at the upgrade wallet |
| `cells-names` | any registration, edit or transfer |

Two things had to be fixed to make this real rather than decorative:

**Watching the owner's address would have missed the case that matters.** An upgrade
recreates the code cell under whatever lock the spender chooses, so a thief's upgrade
pays nothing to the old address. The watch is on the **type-id**, which appears
whoever performs it.

**Every rule in the tool read outputs only**, so a cell consumed and never recreated
matched nothing. Destroying the code cell would freeze every name, because the cell
dep would stop resolving, and it would have gone unseen. `ckb-monitor` gained an
`outPoint` rule that reads inputs (upstream, commit `1e6d274`). It is a separate watch
from the type-id one on purpose: a watch fires only when **every** dimension holds, so
combining them would have required both and missed the destruction.

Verified by spending a real account cell and watching the deployed service log it,
once in the pool and again on commit, rather than by trusting that it would.

**Maintenance:** a legitimate upgrade moves the code cell, so `cells-code-destroyed`
must be repointed at the new outpoint afterwards, or it silently guards nothing. Done
for the term-and-fee upgrade: the watch now points at `0x8500ea2e…:0`.

### Two traps to avoid while implementing this

**Multisig theatre.** An M-of-N where every key belongs to one person is backup with
extra steps, not decentralization. It protects against losing a key; it protects
nobody from us. Either recruit genuinely independent signers, or document that today
it is a single key and that the multisig arrives when there are people to hold it.
Both are defensible. Pretending is not.

**There is no cheap timelock.** The CKB system multisig's `since` is a one-shot cliff,
not a per-operation delay, so "every upgrade waits N days" needs a bespoke lock, which
is new security-critical code and its own audit scope (this is why 0003 declined to
hand-roll one). Until that is worth building, the delay is **procedural**: upgrades are
announced publicly N days ahead. Not enforced by code, but verifiable afterwards, and
honest about which it is.

## Live rates are a display concern, and that is not a consolation prize

Fetching CKB/USD from CoinGecko or Binance in the **browser** is free, safe and worth
doing: both send `access-control-allow-origin: *`, so the page can call them directly,
and a newcomer understands "about $5" where "4900 CKB" means nothing. If the call
fails the figure disappears rather than being guessed, because a wrong number about
money is worse than no number. This shipped.

What it cannot do is set the price, and not only because a script cannot make HTTP
calls. **A fee the payer chooses is a fee the payer minimises.** The contract can only
check a minimum, so if the floor is 250 CKB and the interface asks for 4900, anyone can
build the transaction by hand and pay 250. The contract's floor is the price, always;
everything above it is a suggestion.

## The curve as it stood, worth about a quarter

> Historical. The rent became a flat 240 CKB with [0015](0015-cell-size.md); the fee schedule
> further down is what changed the economics and is what is live.

Priced live while writing this, at $0.00102 per CKB:

| label | rent | in dollars |
|---|---|---|
| 5+ chars | 250 CKB | $0.26 |
| 4 chars | 500 CKB | $0.51 |
| 3 chars | 1000 CKB | $1.02 |
| 1 char | 5000 CKB | $5.11 |

As a refundable deposit that is fine. **As the anti-squatting deterrent it is claimed
to be, it is not:** ten thousand names cost about $2,600 refundable, and since nothing
expires they can be held forever. The curve was designed when the number was abstract.
This is a second, independent reason step 1 (a real term) and step 2 (a real fee) are
not optional.

## The numbers, decided 2026-09-04

Priced at $0.00102 per CKB. The fee is **per year**, on top of the refundable rent,
and it does not come back.

| label | per year | at today's rate |
|---|---|---|
| 5+ characters | 5 000 CKB | $5.10 |
| 4 characters | 20 000 CKB | $20 |
| 3 characters | 80 000 CKB | $82 |
| 2 characters | 200 000 CKB | $204 |
| 1 character | 500 000 CKB | $510 |

Five-plus lands on the same five dollars a year ENS and `.bit` converged on.
Short names are deliberately **cheaper than ENS**, which charges $640 a year for three
characters: a protocol with no demand cannot price like one with demand, and raising a
fee later is easy while lowering it after driving everyone away is not.

**Bounds** (see the correction above for what these are and are not): 0.1x to 10x the
starting figure on every line, so 500 to 50 000 CKB on the 5+ line. That absorbs a
tenfold move in CKB either way; past that the schedule needs a new look anyway.

**Term:** one year by default, ten at most, and renewal buys whole years at the same
rate. The term is derived from `expired_at` rather than carried as a new field, so the
data layout does not change: the contract reads `expired_at - now` (with `now` taken
from the CommitCell's block header, which the client can read exactly at build time)
and charges for `ceil(term / year)`.

## Open

Two left; the third is closed above.

1. **Who holds the keys.** Single key with the multisig deferred, or real external
   signers from the start.
2. **Whether a bespoke lock on the code cell is worth its own audit.** This is now one
   decision covering both the upgrade delay and the enforced price band, since they are
   the same mechanism.
3. ~~**Where the fees go.**~~ **Closed 2026-09-04 for the test network: the JoyID account.** The treasury lock hash is a constant in the contract
   (`0xd9d17703…`, address `ckt1qrfr…wummjn`, the owner of `tecmeup.cell`). **On mainnet the treasury is a plain `secp256k1_blake160`
   key of its own**, lock hash `0x57d926a4…`, held for the protocol alone; TRUST.md records
   the choice. The two paragraphs below describe the test-network arrangement.

   It is deliberately **not** the upgrade wallet: `cells-watchtower` alerts on funds
   arriving there, and a fee on every registration would bury the one alert that
   matters under routine noise. JoyID also has no seed phrase to lose.

   The cost of the choice, so it is on the record: protocol revenue and a personal
   everyday wallet are the same address, so there is no separate ledger for what the
   protocol earned, and anyone watching the chain can see both. Moving it later is an
   upgrade, not a config change.
