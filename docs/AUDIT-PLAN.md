# Cells: adversarial review plan (pass 5)

The brief for the next internal security pass on the contracts. the original audit brief (since retired) is
the scope package for an external auditor and [the security journal](SECURITY-JOURNAL.md) is the record
of what four previous passes found. This is neither: it is an attack plan, written to
find what those four could not.

Read it before starting, and update the hypothesis table as each is killed or confirmed.

## Why another pass, and what it must do differently

The four previous reviews asked, action by action, "is the stated rule enforced?" That
method worked: it found namespace poisoning, the JoyID forgery, two sale-lock payment
bugs and H-1. It is now close to exhausted, because it validates that each validator
does what its own documentation says.

Four things that method structurally cannot see, and which this pass exists to cover:

1. **Interactions between validators, and between script groups.** Every validator was
   audited alone. A CKB transaction runs many script groups, and `paid_to`,
   `require_treasury`, `signed_by` and `require_owner` all read the *whole* transaction,
   not just their own group's cells. Value counted by two groups from one output is the
   exact class that bit the sale lock twice already.
2. **Assumptions shared by the code and its tests.** the original audit brief (since retired) admits this
   happened once: the property test "hard-codes the assumption the contract failed to
   enforce". A test written from the same mental model as the code cannot falsify that
   model. This pass must read the tests looking for agreement, not coverage.
3. **The economic layer.** Every rule can be enforced exactly as written and the system
   can still leak value. No previous pass modelled the numbers.
4. **The off-chain surface.** The worst finding of the last round (JoyID request forgery)
   was in the SDK's `request` module, not in Rust. A review that reads only the contracts would
   have scored that round a clean pass.

## Independence, stated plainly

Whoever runs this pass in-session has also written or reviewed much of this code, which
is a real conflict: self-review reliably misses the bug you reasoned your way into. Three
mitigations, none of which fully removes it:

- Findings are framed as **attacks to build**, not code to read. An exploit either
  produces a transaction the VM accepts or it does not.
- Reviewers are given the code and the invariant, **not the reasoning** behind the
  current design, so they cannot inherit its blind spot.
- Every confirmed finding needs a **control** (below). A control is the only thing that
  distinguishes "I checked" from "I believed".

This does not substitute for a third-party audit. See "What a clean pass licenses".

## Scope

**In:**

- `contracts/crates/cells-core` (layout, parse/serialise, `covers`/`between`,
  `validate_label`, `price_floor`, `registration_fee`, `apply_price_factor`,
  `years_for_term`, `referral_cut`)
- `contracts/contracts/account-cell-type` (all seven actions, genesis token, commit
  reveal, treasury, referral, price cell)
- `contracts/contracts/sale-lock` and `price-cell-type`
- `contracts/contracts/account-lock` (always-success: confirm the type script is
  exhaustive *given* it, on inputs and outputs)
- the deploy and genesis flow (type-id derivation, one-time token consumption)
- the SDK's `request` module and the SDK's `address` module, because signature verification and
  address handling are where the last critical lived

**Out:** the web UI, the resolver (a cache whose every answer is verifiable
against chain, so a dishonest one is detectable rather than trusted), CKB consensus and
the system scripts.

## The four lenses

Each lens is a different question asked of the same code. Run them independently and do
not let one reviewer hold two, because the value is in their disagreement.

### Rust and `no_std`

Not memory safety (there is no `unsafe` to speak of) but the failure modes of hand
written byte handling in release builds.

- Integer behaviour in `--release`: overflow does **not** panic, it wraps. Every `+`,
  `*` and `-` on a value an attacker influences (capacity, fee, factor, years, expiry,
  lengths) must be checked, saturating, or provably bounded. `as` casts that truncate.
- Panics as denial of service. A slice index or `unwrap` on attacker-shaped data aborts
  the script. That is safe for value but can permanently brick a cell if the panic is
  reachable in a state the cell can be moved *into*.
- `unwrap_or` and `ok()` that swallow a real error into a permissive default. Note
  `price_factor` does this deliberately and correctly (every failure falls back to the
  full price); find the places where the same idiom falls the other way.
- **Layout version confusion (v1 vs v2).** The manager field is the newest structural
  change and the least reviewed. Parse a v1 cell as v2 and every field after the
  insertion point shifts. Question to answer: can a cell be constructed whose declared
  version disagrees with its length, such that `owner_lock_hash` is read from bytes the
  attacker controls?
- Round-trip: for every `parse`/`build` pair, does `parse(build(x)) == x` for all
  reachable `x`, including the boundaries (empty records, max label, max years)?

### Nervos and CKB semantics

The traps that are specific to this VM and this cell model.

- **Script group scoping.** `collect()` gathers cells carrying *this* script hash, but
  `paid_to`/`require_treasury`/`signed_by` scan every input and output in the
  transaction. Enumerate what a second, attacker-controlled script group in the same
  transaction can make those functions see.
- **`since` parsing.** `check_commit_since` requires the top byte to equal `0xC0`. Walk
  every flag combination (absolute/relative, block/epoch/timestamp) and confirm no other
  encoding reaches a permissive path, and that the 56-bit mask cannot be gamed.
- **Header binding.** `header_time_seconds` uses `load_header(i, Source::Input)`, which
  is bound to the block containing that input. *Already checked and sound*; confirm no
  other timestamp read uses `Source::HeaderDep` with an attacker-chosen index.
- **Cell deps are attacker-supplied.** `require_parent`, `referral_discount` and
  `price_factor` all read deps. Each must pin identity by a hash that cannot be minted.
  Confirm for each: what happens with zero matches, two matches, and a match whose data
  is malformed?
- Witness structure: `input_type` versus `output_type`, and index-versus-source
  confusion in every `load_*` call.
- Type-id derivation, and whether the genesis token can be consumed in any transaction
  shape other than the intended one.

### Hacking

Not "is the rule enforced" but "what transaction shape did nobody imagine".

- Multi-group and batched transactions: two namespaces, an account action plus a sale, a
  register plus a renew, the same cell serving two roles.
- Griefing and availability: can an attacker make a cell that is valid to create but
  impossible to ever spend again, freezing an id range? (This was the namespace
  poisoning bug; confirm the `CellLockNotAccountLock` pin is total.)
- Mempool and ordering: commit-reveal is live, so attack the *commit* rather than the
  reveal. Can a commitment be blocked, replayed across namespaces, or made to mature
  under someone else's control?
- Anything that makes the *predecessor* relationship lie.

### Finance

The system can enforce every rule correctly and still lose money. Model the numbers, do
not reason in prose.

- **Referral self-dealing.** `signed_by(owner)` disqualifies an inviter who spent a cell
  in the transaction. Two locks appear to defeat it: own a name whose owner lock is L1,
  fund the registration from L2, pay the cut to L1. See H1.
- **Recycle arbitrage.** `recycle` pays the expired name's deposit to the recycler as a
  keeper bounty (M-1, resolved by design). Model deposit versus fee versus the cost of
  the transaction: is there a label length or term where registering and later recycling
  your own name is profitable?
- **Sub-name economics.** A sub-name is priced on the full dotted length, so
  `shop.alice` is charged as ten characters. Is there a length where minting sub-names
  is cheaper than the value of the list positions they occupy?
- Rounding: every division in the fee, referral cut and sale split. Who receives the
  remainder, and can it be driven to favour the payer?
- The treasury-pays-itself carve-out is documented and accepted; confirm it cannot be
  extended to a lock that merely *resembles* the treasury.

## Hypotheses, ranked

Derived while scoping. Confirm or kill each; add new ones as they appear.

| # | Lens | Hypothesis | Status |
|---|---|---|---|
| H1 | finance | Self-referral with two locks yields a permanent 10% discount. `signed_by` catches only the case where the inviter's own lock signs; funding from a second lock evades it while `paid_to(L1)` is satisfied by paying yourself. | **strong, untested** |
| H2 | rust | A v1/v2 length-versus-declared-version mismatch shifts field offsets so `owner_lock_hash` or `manager_lock_hash` is read from attacker bytes. | open |
| H3 | nervos+finance | One output counted as payment by two script groups (the class that bit sale-lock twice), across two namespaces or an account action plus a sale. | open |
| H4 | finance | Register-then-self-recycle is profitable at some label length or term. | open |
| H5 | rust | A reachable panic in a parse path bricks a cell permanently. | open |
| H6 | rust+finance | Truncation or wrap in `apply_price_factor` / `registration_fee` / `years_for_term` at boundary values. | open |
| H7 | hacking | Sub-name or commit griefing that blocks a specific name more cheaply than owning it. | open |
| H8 | off-chain | A second signature-shape confusion in the SDK's `request` module, in the same family as the JoyID break but for another wallet. | open |
| H9 | method | A test asserts the same wrong thing the code does, hiding a real bug behind a green suite. | open |

Already checked while writing this plan, and **closed**, so do not spend the pass on
them: the header-dep binding is sound; the price cell is pinned by a type-id hash and
every failure path falls back to the full price; the referral cut cannot be paid by the
same output as the treasury (explicit `!= TREASURY_LOCK_HASH`); `saturating_add` in
`paid_to` cannot be driven to saturation because total CKB supply is below `u64::MAX`.

## What counts as a finding

The repo's existing standard, kept because it is the right one:

1. A **VM test that fails** against the current contract, in `contracts/tests`.
2. A **control**: remove the guard, and the test must go red for the stated reason. A
   check with no control is not evidence, only a belief that happened to be green.
3. The **transaction that exploits it**, written out, not described.
4. For economic findings, a **numeric model** with the actual constants, not prose.

Severity: what an attacker gains, what a victim loses, and what it costs to try. A
finding nobody can afford to exploit is still a finding, but it is not a High.

## What a clean pass licenses, and what it does not

It licenses saying the contract survived a fifth adversarial pass with the hypotheses
above written down in advance and each one either exploited or killed with a control.

It does **not** license "there are no holes". Five internal passes have found something
every time, including one CRITICAL in the round that was expected to be clean. The
honest claim after this pass is a bounded one: these attack classes were tried and these
specific ones failed. That is worth stating on screen exactly that way, which is what
decision 0010 already commits to.

It also does not substitute for third-party review, for the reason in "Independence".

## Order of work

The upgrade-key decision (T-1) must come **after** this pass, not before: locking or
burning the code cells forecloses fixing whatever this finds. That ordering is already
in the security journal's priorities and this plan does not change it.
