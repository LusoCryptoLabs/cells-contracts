# 0010: Shipping to mainnet without an external audit

Status: **Decided 2026-09-04.** The external audit no longer blocks mainnet. It is
replaced by the three things below, which are weaker, and this file says how much
weaker rather than pretending otherwise.

Amends the original audit brief, since retired (what was still true in it is in SPEC.md and
the security journal), which said the audit was the gate.

## What replaces it

1. **A structured adversarial review**, run 2026-09-04: four independent passes over
   the ~900 lines in scope, each attacking one surface, each required to produce a
   buildable transaction rather than a worry. What it found is below, and it is the
   reason this file is not a formality.
2. ~~**The status is on the screen**, not in a footnote.~~ **Withdrawn 2026-09-05.** The app did render "the contract has not been reviewed by an
   independent security auditor" next to the price and in every footer. It was withdrawn; the component now names the network only, because somebody about
   to pay still needs to know the coins are test coins.

   This file says so rather than quietly keeping the old sentence, because a decision
   record that describes a screen which no longer exists is worse than no record. **Two
   of the three things that replaced the audit remain: the adversarial review, and the
   low launch fee.** The audit status is still stated in the help page and in the terms,
   which say a review comes before any deployment where real value is at stake; those
   are documents somebody opens deliberately, not a notice shown to everyone.

   The consequence, stated plainly and not argued: at mainnet the product will neither
   say it is unaudited nor show the code, unless the repo is opened. Those two decisions
   are now linked, and the second one was closed for the contracts on 2026-09-23.
3. **A low starting fee at mainnet launch**, so nobody is exposed to much while the
   code is new. The number is a launch decision, not a testnet one.

## What the review found, and why that cuts both ways

Five holes, all closed the same day, all with tests that were run against the guard
disabled to prove they can fail. Full detail in [the security journal](../SECURITY-JOURNAL.md).

The worst was a **break in name uniqueness**, the one guarantee the protocol exists to
provide. The root sentinel could be recycled by anyone, because `validate_recycle`
never excluded it and the root was created with `expired_at = 0`. With the root gone,
the id-derivation exemption written as "any cell whose id is zero" became a licence to
mint a cell with id zero and **any label**, including one already registered. Two live
cells, same name.

Three of the four reviewers found it independently. The property test that
the original audit brief (since retired) cites as evidence for the uniqueness invariant could never have
found it: its model excludes the root from recycling and id zero from registration, the
exact two assumptions the contract failed to enforce.

**The honest reading of that is not "the review worked".** It is that a protocol whose
whole claim is uniqueness shipped a break in uniqueness, and internal review missed it
for three months while the documentation recorded the surrounding finding as *fixed*.
An external audit would have found this. That argument was made and lost, and this file
records that it was made.

## What the comparable actually did, since it was researched rather than assumed

| | `.bit` | Cells |
|---|---|---|
| mainnet | 2021-07-22 | 2026-09-21 |
| first public audit | 2024-04-10, in-repo PDF | none |
| audit vs mainnet | 2 years 9 months after | none yet, before or after |
| fund-securing on-chain code | open source, audited | MIT; the contracts public since 2026-09-23, the application not |
| admin control | super lock multisig + kill switch, disclosed in `.env.mainnet` | type-id upgradeable, single key, disclosed in 0009 |

**`.bit` did not wait for an audit either.** So "everyone audits first" is false in this
ecosystem, and that is the strongest fact in favour of shipping.

But `.bit`'s audit, when it finally came, found ten issues in code that had been live
for nearly three years, including a multisig threshold bypass by signature reuse and a
buffer overflow rated "straightforward" to trigger. Nothing was exploited. The window
existed anyway. That is the realistic expectation here too.

The auditors also said something that applies directly: CKB has no best-practice corpus
and no vulnerability database for type scripts, which makes both self-review and paid
review harder than on Ethereum. Confidence in unaudited CKB code should be *lower* than
the same confidence would be elsewhere, not higher.

## The conditions this decision depends on

If any of these stops being true, the decision should be revisited.

- **The upgrade key works and is backed up.** Ship-then-audit is only survivable
  because a finding can be fixed. Unreviewed code that *cannot* be fixed is worse than
  either problem alone, and this project has already lost one upgrade key.
- **Open source, and admin control disclosed. NOT MET TODAY.** The repo
  (`LusoCryptoLabs/LCL.cells`) is MIT licensed and **private**, so the code securing
  people's names is not readable by the people trusting it. It was the one condition here that mainnet opened without. `.bit` bought credibility without an early audit by being open
  and by disclosing its admin lock in a committed file; that costs nothing and is the
  obvious substitute for an audit. **Publish the repo before mainnet, or the "not
  audited" notice is asking people to trust code they cannot read.**

  **2026-09-23: met for the contracts.** They and this documentation are public at
  `github.com/LusoCryptoLabs/cells-contracts`, and the mainnet binaries reproduce from them
  byte for byte. The application is not public.
- **The indexer and resolver get the same scrutiny as the cells.** ENS has been audited
  repeatedly since 2017 and still shipped a null-byte lookalike bug in its *subgraph*
  that produced real impersonation incidents. For a naming protocol the contract is not
  the whole attack surface.
- **No bug bounty exists.** The Nervos Foundation's bounty excludes third-party code,
  and neither comparable runs its own. Cells has neither an audit nor a bounty, so it
  has no external eyes at all beyond whoever reads the repo.
