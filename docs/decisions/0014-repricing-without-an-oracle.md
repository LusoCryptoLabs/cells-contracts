# 0014: Repricing without an oracle

Status: **Decided 2026-09-06, design refined 2026-09-07, built and proved on Pudge
2026-09-07.** The "bring it forward" trigger in the decision below fired the day it was
written (mainnet this week, a hundred names expected), so it was built, on testnet first;
see "Built and proved" at the end.

Reopens the pricing question that [0009](0009-economics-and-the-upgrade-key.md) closed
with "the fee is a CKB amount, a constant in the contract, changeable only by an upgrade".
That decision stands. What changes here is that the *cost of using* the escape hatch is
now written down, along with the design to make it cheap, and the trigger for building it.

## Why it was reopened

0009 accepted an honest cost: "if CKB moves an order of magnitude, the fee is wrong until
an upgrade fixes it. We accept a slow, visible correction over a fast, fragile automatic
one." The maintainer has since said plainly that CKB will not stay where it is and that
manually tracking it is not something he wants to do. So the question is narrow: **can
repricing be automated without acquiring an oracle we have to run forever?**

Priced while writing, at $0.00112 per CKB, the 5+ line is 5,000 CKB = **$5.58**. The
target was five dollars. Nothing is wrong today; the question is about the next 10x.

## What a four-way review found

The proposal on the table was a "bounded keeper": move the schedule into a config cell,
let a limited key nudge it, and bound the damage with a price band, a step limit and a
cooldown enforced by the contract. Four reviewers (advocate, sceptic, researcher, red
team) were run against it. Four findings survived.

### 1. A bounded keeper does not dodge open decision 2, it *is* open decision 2

Cell dep scripts do not execute. `account-cell-type` is not invoked in the transaction
that updates the price cell, so the band, the step limit and the cooldown **cannot live
there**. They can only live in the price cell's *own* type script, which must therefore
also reimplement type-id uniqueness, because a cell carries one type script and not two.

That is new security-critical code with its own audit scope: exactly the bespoke-lock cost
0009 declined to pay for the upgrade delay and the price band. The keeper does not avoid
that cost, it relocates it. 0009's line holds and is worth repeating here, because it is
the whole trap: *"a bound written beside the number it guards guards nothing against the
only party able to change the number."*

### 2. This cell existed once, and was removed for cause

`config-cell-type` was deleted as security finding **H-1** ([the security journal](../SECURITY-JOURNAL.md)):
it was located by the type hash of *any* instance with empty args, so an attacker could
mint their own and forge a second root. `ConfigCellMissing = 33` is still sitting in the
error enum as a scar.

A real **type-id** (args bound to a spent outpoint, unique by construction) closes H-1's
specific hole. It does **not** close the availability problem, which is the reason 0009
rejected the oracle in the first place: a consumed or malformed dep makes every
registration transaction invalid, bricking the only revenue path on a dependency we
control but can still fumble.

### 3. The ecosystem still offers no way out

This confirms, three years on, the survey 0009 already did.

| system | denomination | mechanism |
|---|---|---|
| ENS | USD-pegged | `StablePriceOracle` reading a Chainlink aggregator |
| Basenames | USD-pegged | same codebase, its own oracle contracts |
| Solana Name Service | USD | sidesteps oracles by charging in **USDC** |
| Handshake | native HNS | auction, no peg |
| Stacks BNS | native STX | price fixed at namespace reveal, **immutable** |
| Arweave | native AR | prices bytes off difficulty, not USD |

Everything that truly holds a dollar price uses an oracle or a stablecoin. There is still
**no credible price oracle on CKB**: the Chainlink integration announced in 2020 was never
deployed, and the CKB oracle repos remain single-author prototypes. CKB stablecoins (RUSD,
USDI) exist but are far too small to require a buyer to hold one for a $5 name.

The cautionary tale is **Stacks BNS**: its price function cannot be changed at all, `.btc`
drifted to roughly $0.30 a year after a ~5x move, and proposals to fix it reached no
consensus. That is the failure mode of pricing in a native token *and* making it immutable.

**Cells is not BNS.** The upgrade key is precisely the escape hatch BNS lacks. We are not
deciding whether we *can* reprice; we can. We are deciding what it costs.

### 4. The correction is rarer, and the bot slower, than it feels

Modelled against realistic small-cap volatility, a tolerance band of $2 to $15 is left
roughly **0.6 to 2.3 times a year**: one to two hours annually. And a 25%-per-day step
limit needs about **nine days** to chase an 8x move, then nine more to come back. The
keeper would be wrong for a fortnight during exactly the event that justified building it.

Automation buys less here than it appears to.

## Decided

**Not now, and never as a standalone testnet upgrade.** Two cheap things instead, then a
decision at mainnet.

1. **A drift alert. No key, no contract change, no trust surface.** A daily job beside
   `cells-watchtower` computing `5,000 CKB x rate` and firing only when it sits outside
   $2 to $15 for three consecutive days (so a wick does not page anyone). Its real job is
   to *produce the evidence* that settles this question in twelve months: if it fires more
   than three times in a year, the keeper is justified; if it fires once, it is not.
2. **A a script (kept with the application, not in this repository) script.** the deployment runbook (kept with the application, not in this repository) lists five files that must stay
   in sync after any deploy and there is no script that does it. That is the actual pain
   behind "repricing is expensive", and fixing it makes *every* upgrade cheaper, not just
   pricing ones.

**Then decide at mainnet.** The cost list for the keeper (rebuild, sync five files,
republish reproducible hashes, repoint `/verify`) *is* the mainnet deploy checklist.
Shipping it separately on testnet pays that bill twice and spends H-1-shaped risk budget
on play money, where a mispriced year across ~10 names costs about six dollars.

**Bring it forward only if** CKB moves more than 3x from $0.00112 while still on testnet
*and* there are more than 100 live names.

## The design, if and when it is built: a discount, not a price

The redesign that came out of the red team is materially better than what went in, and it
turns on one idea:

> **The hardcoded schedule stays in the contract as the ceiling and the fallback. The
> price cell may only ever discount from it.**

### The read rule

The price cell holds **one number**, a discount factor, and it applies to every tier at
once:

```
effective_fee(len, years) = code_schedule(len, years) x factor
factor in [63 / 5000, 1]  =  [0.0126, 1]    (stored as basis points, 126..10000)
```

If the price cell dep is absent, unresolvable, malformed, or the factor is outside that
range, then `factor = 1` and the code schedule applies unchanged.

**The fallback is the expensive direction, so every failure costs the payer money rather
than the treasury.** That is the correct way round, and it must be built deliberately:
`account-cell-type` already uses a permissive `Err(IndexOutOfBound) => return Ok(..)`
idiom in several dep scans (main.rs:141, 376, 402, 428). Copied carelessly here, a missing
dep would mean a free name. The fallback must be the code schedule, never zero.

**One factor, not five prices.** An earlier draft of this record gave the price cell a
five-entry table, one per label length. That was worse. A single factor scales every tier
together, so the ladder keeps its shape structurally and needs no ordering check; there is
one value to bound, one to step-limit, and one to parse. It fell out of asking which tier
hits the floor first (below), which is the question the table was hiding.

### What that one idea kills

| threat | why it dies |
|---|---|
| bricking registration (0009's stated reason for rejecting oracles) | a missing price cell prices at the code schedule; nothing stops |
| a stolen key forcing a 10x renewal shock on existing holders | the effective price can never exceed the published code schedule |
| `/verify` no longer proving the price | it still proves the **ceiling**, the most anyone can be charged |
| griefing pending commits by moving the outpoint | a client can always omit the dep and pay the code price |
| a compromised update collapsing the premium ladder | every tier moves by the same factor; a 1-char name stays 100x a 5+ name |

The asymmetry also matches the urgency profile. CKB rising makes names expensive and needs
a *fast cut*, which the keeper does. CKB falling makes names cheap, which costs revenue but
harms nobody, and is fixed at leisure with the cold key.

### The update rules, in the price cell's own type script

Enforced when the cell is spent and recreated:

- exactly one price-cell input and one output (no destruction, no duplication)
- `output.lock == input.lock` and `output.capacity >= input.capacity`
- data is `version | factor` (a u32 in basis points) and nothing else; length and version
  byte unchanged
- `factor <= 10000`: discount only, never above the code schedule
- `factor >= 126`: the cheapest tier never falls under the treasury minimum (see the floor)
- **step limit**: `new*4` within `[old*3, old*5]`, i.e. plus or minus 25% per update. This
  needs no stored history, because the update transaction contains both the old value
  (the input) and the new one (the output).
- **cooldown**, 24 hours *(amended 2026-09-12: six hours, `21600`; see the end)*: require the
  price-cell **input's `since`** to be a relative-timestamp (flag `0xC0`) with
  `delay >= 86400`. The cell's age *is* the time
  since the last update, because every update recreates it, and CKB consensus refuses to
  include the transaction early. No timestamp field, no header dep, no self-attestation.
  Both primitives already exist here: `check_commit_since` (0xC0) and
  `require_expired_since` (0x40) in `account-cell-type`.

### The floor is 63 CKB, and it is a brick-guard, not a security control

The fee is paid as a **treasury output**, and a cell cannot hold less than its own bytes
cost. The treasury is a JoyID lock with 22-byte args, so its smallest possible output is
8 + 33 + 22 = **63 CKB**. (The folklore figure of 61 is for a standard 20-byte-args lock,
which is why this must be computed from the real lock and not quoted; the SDK already
does, from the real lock.) On mainnet the treasury is a plain `secp256k1_blake160` key
with twenty-byte arguments, so its smallest output is 61 CKB there and the 126 basis-point
floor is two CKB more conservative than it needs to be; it was kept. Below 63 the fee output is unconstructible and registration
bricks itself, so 63 is the floor and 126 basis points is its expression.

With one factor, the cheapest tier is the only one that can reach it. At maximum discount:

| tier | code schedule | at factor 0.0126 |
|---|---|---|
| 5+ chars | 5,000 | 63 |
| 4 chars | 20,000 | 252 |
| 3 chars | 80,000 | 1,008 |
| 2 chars | 200,000 | 2,520 |
| 1 char | 500,000 | 6,300 |

The range is 5,000 to 63, about **79x**: it holds ~$5 until CKB reaches roughly $0.089,
which covers any realistic appreciation.

**What that costs, decided 2026-09-07 with eyes open.** At 63 the floor no longer limits a
stolen key at all. The worst case is names at 63 CKB, about seven cents, and the namespace
bought cheaply. The step limit and cooldown still bound the *speed* (25% a day took about
fifteen days to walk 5,000 down to 63; the amended rule, a sixteenth every six hours, takes
about seventeen), so it is detectable, but from here the security
rests entirely on the step limit, the cooldown, and how fast the operator responds with
the cold key, not on the floor. This is the deliberate choice of peg range on the way up
over damage limitation. The floor is a dial, and a higher one trades the other way: at
2,500 the peg holds only through a 2x but a thief can at most halve revenue. 63 is the
maximum-range setting.

### Traps to avoid while implementing

- **Find the cell by type-id at runtime, never by a hardcoded outpoint.** The outpoint
  moves on every update. This is the same maintenance trap 0009 recorded for the
  `cells-code-destroyed` watch, and the reason `cells-watchtower` should watch the price
  cell by **type-id**, which survives updates.
- **Re-validate the factor's range at read time**, not only at update time, so a
  compromised or buggy update path is still bounded where the money is checked.
- **Front-running is real and cheap to accept.** A published rule ("the discount is
  removed when drift exceeds X") invites prepaying ten years just before a rise. Cap the
  prepay term or accept it; do not pretend it is not there.
- **CKB falling is not handled here.** `factor <= 1` means the fee can never exceed the
  code schedule, so if CKB drops and names become too cheap, raising the price is a
  cold-key upgrade. That is the accepted half of the trade above.

## What this costs, stated plainly

`registrationFeeCkb()` stops being a pure constant and becomes a value read from the
chain. It is used in the SDK's `codec` module, twice in the SDK's `client` module, by
`referralCutCkb` which derives from it, in three proof scripts, and in `RegisterPanel.tsx`
and `Renew.tsx`, both of which compute it during render and would gain a loading state on
the two screens where somebody decides to pay. The Help page's price table is typed into
the prose and would have to read live values or stop quoting numbers.

And the honest trust cost: `/verify` today proves the code and therefore the price. After
this it proves the code, the guardrails and the ceiling, but the number actually charged
is mutable state behind a hot key. That is a real reduction in what a stranger can check,
it is smaller than it would have been without the discount-only rule, and public material
must describe it accurately.

## Built and proved on Pudge, 2026-09-07

The trigger in "Decided" fired the same day it was written: mainnet is being cut this
week and more than a hundred names are expected within a fortnight, so the keeper was
built, on testnet first, exactly as that section asked. What is live:

- `price-cell-type` as a type-id code cell (`0x2c396177…:0`), and the one price cell
  (`0xb74dce60…:0`) under a new pricing key, created at a factor of 9000. Its own script
  validated the type-id args on creation: the first live proof of the H-1 fix.
- `account-cell-type` upgraded in place to the build that reads it (`0x619cb590…:0`), with
  the cell's type hash as the cells-core default, so a plain build reproduces the binary.
- Proved by a proof script (kept with the application, not in this repository) with real transactions: a registration with the
  cell as a dep paid **4 500 CKB**, the schedule times the factor (`0x4976480c…`); one
  without the dep paid the full **5 000 CKB** and was accepted (`0x6d69c675…`), the
  fail-safe direction; an update inside the cooldown was refused by consensus as immature.
  The positive update needs the cell to be a day old (a script (kept with the application, not in this repository), or the keeper);
  six hours since the amendment below.
- The keeper runs every three hours, one instance per network, on our server. Its first run read the
  live cell, took the median of three price feeds and held at 0.3% drift, a 5+ name being
  $5.01. The watchtower watches the price cell by its type-id args and the code cell by
  outpoint. The resolver reports the factor on `/health`; `/verify` covers four contracts.

Every rule of both scripts has a mock-VM case (`contracts/tests/tests/price_cell.rs`, and
the price cases in `account_cell.rs`). The evidence log the keeper writes is the record
"Decided" asked for: count its `moved` lines in a year.

## Open

1. **Whether the price cell's type script is worth its own audit scope.** This is open
   decision 2 from 0009 wearing a different hat, and the answer should be the same answer.
2. **Whether the keeper runs at all, or the alert plus the cold key is simply enough.**
   The alert from "Decided" above exists to answer this with evidence rather than
   temperament. Revisit twelve months after it starts logging. **It runs**, on both networks
   since 2026-09-23; the evidence log decides whether it stays.

## Amended 2026-09-12: six hours and a sixteenth

**What changed.** `PRICE_COOLDOWN_SECS` from 86 400 to 21 600, and `price_step_ok` from a
quarter either way (`new x 4` in `[old x 3, old x 5]`) to a sixteenth (`new x 16` in
`[old x 15, old x 17]`). Two constants in `cells-core`, mirrored in the SDK.

**Why.** The keeper could only correct the price once a day, and on a day the coin moved
7% the chain was charging 7% over the list for most of that day. On the coin path that is
a discount that drifts; on the card path it is a real number on a real receipt, $35 on a
$500 name, with the buyer told the coins are dearer today than the list says. Correcting
four times a day makes that line rare and small.

**Why the two numbers moved together.** They are a pair, and the pair is the theft guard:
a stolen pricing key can move the price by at most one step per cooldown, so cooldown and
step size together set how much damage a day allows before a person wakes up. A quarter
once a day and a sixteenth four times a day allow the same: (15/16)^4 is 0.77, against
0.75. Shortening the cooldown without shrinking the step would have let a stolen key take
68% off in a day. Any pair with the same product was equivalent on safety; six hours was
chosen because it covers the coin's daily swings (the worst in the log, 9%, is caught in
two steps) with the fewest transactions.

**How it shipped.** In place, by type id, so the code hash and the price cell's type
script are unchanged and the hash of it baked into `account-cell-type` still holds:
`price-cell-type` at `0xec7c0690…` (tx `0xec7c0690466942c6a75c6de0eec3e544505e3b77bf131847f233f01c26565c77`).
Recompiling `cells-core` changed the bytes of `account-cell-type` as well, with no change
to its source (it references neither constant): the amendment added six lines of comment,
and `overflow-checks` bakes a `core::panic::Location`, carrying the **line number** of the
site in `cells-core`, into every bounds check that inlines from it. Exactly one byte moved,
at `0xdc0`, a line going 625 to 626; changing the constant's value, or arithmetic
`account-cell-type` never calls, moved nothing at all. It is line positions, not contents
(measured in the deployment runbook (kept with the application, not in this repository) 3c). Cosmetic, and still a MISMATCH, so rather than leave the
deployed binary unreproducible from the repo
it was upgraded in place too, same type id, same 39 888 bytes
(tx `0x38bd70ca61dd2bc5db2b4b2491ad45cc270392c114fcdab94fba40ab93f1b119`), and `verify-onchain`
reports all four contracts equal to their builds.

**Proved, with a control.** The price cell was 16.6 hours old. At 15:11 UTC the keeper's
timer ran against the old contract and was refused: `cooldown`, "the cell is younger than
a day". At 15:13, against the new one, the same keeper moved it, and moved it to 8 921
rather than to its target of 8 880, because the step was clamped to a sixteenth of 9 515
(tx `0x3b3c881d3f45df039a2e42ed346de50f08ba24cc7bec297b7f93242df7365ecb`). Both new rules in one
transaction, two minutes after the old rule had refused the same move. A records edit
through the recompiled `account-cell-type` then went in and out of `maria.cell` unchanged.

**What did not change.** The floor, the ceiling, the pricing key, the keeper's band (2%)
and its timer (every three hours, which now acts within three hours of a cooldown
expiring). The keeper's copy of the SDK had to travel with `deployment.json`: with the
old copy it would have asked for a full step and been refused for the wrong reason.
