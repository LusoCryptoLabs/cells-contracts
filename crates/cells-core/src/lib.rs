//! Cells protocol, shared core.
//!
//! Pure, dependency-free logic that is identical on-chain (no_std) and in host
//! tests (std). The two things that live here are (1) the fixed `AccountCell.data`
//! layout reader and (2) the uniqueness linked-list ordering math, the single
//! highest-risk part of the protocol (see ../../../docs/SPEC.md §3).
#![cfg_attr(not(test), no_std)]

extern crate alloc;
use alloc::vec::Vec;

/// Length of an account id: `blake2b(label)[0..20]`.
pub const ID_LEN: usize = 20;

/// A 20-byte account id. Compared lexicographically (big-endian byte order).
pub type Id = [u8; ID_LEN];

// --- AccountCell.data fixed layout, v3 (decision 0015) ----------------------
//
// One layout, a version byte first, and every hash that only ever has to be MATCHED
// cut to 20 bytes. The id is not stored at all: it is `blake2b(label)[..20]`, which the
// contract already required of every stored id, so the field carried twenty bytes of
// something the label determines. The manager is always present (equal to the owner
// when there is no delegation), which costs undelegated names twenty bytes and buys
// the end of the v1/v2 split, where a version marker shared a byte with the label's
// first character and two layouts had to be told apart by a charset argument.
//
// Truncation follows one rule (docs/decisions/0015-cell-size.md): a field an attacker
// must match against a value someone else fixed is a targeted second preimage, 2^160
// at twenty bytes; a field the same party can grind on both sides is a birthday
// problem, 2^80. Owner, manager and the namespace are the first kind. The witness
// hash is the second, and stays at 32.
//
//   [0]        version, always VERSION_V3
//   [1..33]    witness_hash, blake2b of the records payload (32, not truncated)
//   [33..53]   next, the successor id in the ring
//   [53..58]   expired_at, unix seconds, 5 bytes little-endian (good until year 36,812)
//   [58..78]   owner_lock_hash[..20], the auth identity
//   [78..98]   manager_lock_hash[..20], == owner when undelegated
//   [98..]     label
pub const VERSION_V3: u8 = 0x03;
pub const OFF_VERSION: usize = 0;
pub const OFF_WITNESS_HASH: usize = 1; //  [1..33]
pub const OFF_NEXT: usize = 33; //         [33..53]
pub const OFF_EXPIRED_AT: usize = 53; //   [53..58]
pub const OFF_OWNER: usize = 58; //        [58..78]
pub const OFF_MANAGER: usize = 78; //      [78..98]
pub const OFF_ACCOUNT: usize = 98; //      [98..]
pub const DATA_HEADER_LEN: usize = OFF_ACCOUNT;
/// Length of an owner or manager identity: a CKB lock-script hash, truncated.
pub const OWNER_HASH_LEN: usize = 20;
/// Length of the namespace id carried in the type script's args: the genesis
/// token's type hash, truncated.
pub const NAMESPACE_LEN: usize = 20;
/// Bytes of `expired_at` on the cell.
pub const EXPIRY_LEN: usize = 5;
/// The largest expiry the cell can carry: 2^40 - 1 seconds.
pub const MAX_EXPIRED_AT: u64 = (1u64 << 40) - 1;

/// The root sentinel's owner: no owner (it is protocol-owned, never edited).
pub const ROOT_OWNER: [u8; OWNER_HASH_LEN] = [0u8; OWNER_HASH_LEN];

/// The genesis root account's id (sentinel). It covers the whole id space and is
/// exempt from id-integrity, since its label is not a real name (SPEC §3.3).
pub const ROOT_ID: Id = [0u8; ID_LEN];

/// CKB-style blake2b-256 (personalization `ckb-default-hash`).
pub fn ckb_blake2b256(data: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    let mut hasher = blake2b_ref::Blake2bBuilder::new(32)
        .personal(b"ckb-default-hash")
        .build();
    hasher.update(data);
    hasher.finalize(&mut out);
    out
}

/// `id = blake2b(label)[0..20]` (SPEC §2.1). `label` excludes the `.cell` suffix.
pub fn account_id(label: &[u8]) -> Id {
    let h = ckb_blake2b256(label);
    let mut id = [0u8; ID_LEN];
    id.copy_from_slice(&h[..ID_LEN]);
    id
}

/// Maximum label length (bytes == chars, since the charset is ASCII).
pub const MAX_LABEL_LEN: usize = 40;

/// Minimum capacity (shannons) a newly-registered name must lock. **Flat.** CKB
/// capacity is *refundable rent* (reclaimed when the name is recycled), not a burn.
/// Enforced on-chain in `register` and mirrored off-chain so clients fund correctly.
///
/// It used to scale with length, 5,000 CKB at one character down to 250 at five or
/// more, described as anti-squatting. It was not: the rent comes back in full, so a
/// squatter's only cost was the opportunity cost of a few euros. What actually deters
/// squatting is `registration_fee`, which does **not** come back and which is still
/// graduated by length.
///
/// The old schedule also sat BELOW CKB's own rule that a cell must hold its own size,
/// for labels of 33 characters or more, and for any delegated v2 name of five or more.
/// The contract accepted cells consensus then refused, so those names could not be
/// registered at all. A flat floor clearing the worst case removes that whole class of
/// "valid here, rejected there".
///
/// 240 is the worst case plus room. Under the v3 layout a 40-character name occupies
/// 8 (capacity) + 33 (lock) + 53 (type, 20-byte args) + 98 (header) + 40 = 232 CKB,
/// whether or not it is delegated, since the manager field is always present. The
/// old layout's 291 was measured against the node (scripts/38-cell-size-probe.mjs);
/// measure this one the same way before locking anything to it.
pub fn price_floor(_label_len: usize) -> u64 {
    240 * 100_000_000
}

// --- The term, and what it costs (decision 0009) ---------------------------

/// Seconds in a year as this protocol counts one: 365 days flat. A leap-day
/// correction would buy a registry nothing and would make the fee depend on which
/// year you happened to register in.
pub const SECONDS_PER_YEAR: u64 = 365 * 86_400;

/// A name is bought for whole years, at least one and at most ten. Before 0009 the
/// only rule was a one-day floor, so `register` defaulted to the year 2096 and
/// nothing ever came up for renewal.
pub const MIN_TERM_YEARS: u64 = 1;
pub const MAX_TERM_YEARS: u64 = 10;

/// Whole years covered by a term in seconds, rounded **up**: any remainder buys
/// another year, so no part of a term is ever free.
pub fn years_for_term(term_seconds: u64) -> u64 {
    term_seconds.saturating_add(SECONDS_PER_YEAR - 1) / SECONDS_PER_YEAR
}

/// One year in every five is free, so a ten-year term is billed as eight.
///
/// The discount is on the term and not on the name, so it is the same proportion
/// for a one-letter name as for a forty-letter one. Time bought in advance is the
/// only thing it rewards, and that is the thing a registry can most afford to give:
/// the money arrives sooner and the name stops coming up for renewal.
pub const YEARS_PER_FREE_YEAR: u64 = 5;

/// Whole years actually charged for a term of `years`.
///
/// Note the flat steps this creates: four years and five cost the same, and so do
/// nine and ten. That is deliberate. At the step there is never a reason to buy the
/// shorter term, which is the whole point of offering the longer one.
pub fn charged_years(years: u64) -> u64 {
    years.saturating_sub(years / YEARS_PER_FREE_YEAR)
}

/// What a sub-name's fee is divided by: a child is charged a fifth of what its
/// parent is charged for the same term.
///
/// Priced from the parent rather than from its own length, so a short parent makes
/// dearer children than a long one and a namespace is worth what its root is worth.
/// The child's own length buys nothing, which is right: `a.telmo` is not a
/// one-letter name, it is one name inside somebody else's.
pub const SUBNAME_DIVISOR: u64 = 5;

/// The registration fee (shannons) for `years` whole years.
///
/// This is **not** `price_floor`. That is refundable rent, held in the name's own
/// cell and returned when the name is recycled. This leaves the registrant for good
/// and must be paid to `TREASURY_LOCK_HASH`, at `register` and again at `renew`.
/// It is what the protocol earns; before 0009 it earned nothing and structurally
/// could not.
pub fn registration_fee(label: &[u8], years: u64) -> u64 {
    const CKB: u64 = 100_000_000;
    let (base, divisor) = match parent_label(label) {
        Some(parent) => (parent, SUBNAME_DIVISOR),
        None => (label, 1),
    };
    let per_year: u64 = match base.len() {
        // An empty label never reaches here (the charset check rejects it first),
        // but pricing it at zero would be a quiet way to make a name free.
        0 => u64::MAX,
        1 => 500_000,
        2 => 200_000,
        3 => 80_000,
        4 => 20_000,
        _ => 5_000,
    };
    // Every figure in the schedule divides by five exactly, so a child's price is
    // exact and the question of which way to round never arises.
    per_year.saturating_mul(CKB).saturating_mul(charged_years(years)) / divisor
}

/// The inviter's share of a registration fee, in percent (decision 0011).
///
/// Ten, the rate `.bit` pays. It comes **off** the treasury's share rather than on
/// top of the price, so a name costs the buyer the same whether anyone invited them
/// or not, and the protocol funds its own growth out of revenue.
pub const REFERRAL_PERCENT: u64 = 10;

/// What an inviter is owed on a fee of `fee` shannons.
///
/// Divides before it multiplies: the rounding goes to the treasury, and the product
/// cannot overflow even for the `u64::MAX` an empty label prices at.
pub fn referral_cut(fee: u64) -> u64 {
    (fee / 100).saturating_mul(REFERRAL_PERCENT)
}

/// The protocol's share of a sale, in percent. **One since 2026-09-14** (0012, 0023).
///
/// Taken the way the referral's tenth is: **the advertised price is what the buyer
/// pays.** A referral comes off the treasury's share so a name costs the same with or
/// without an invitation; a sale fee comes off the seller's proceeds, so a name listed
/// at a thousand is bought for a thousand and the seller keeps nine hundred and ninety.
/// Lowering it raises the smallest listing from about 630 CKB to about 6,300, because
/// the fee has to exist as a cell; `minListingPriceCkb` derives that from this number.
pub const SALE_FEE_PERCENT: u64 = 1;

/// The smallest a cell under the treasury's lock may be, in shannons.
///
/// Not a policy either: CKB makes every cell hold at least its own bytes, and this lock
/// occupies 63 of them (8 capacity, 32 code hash, 1 hash type, 22 args). It is written
/// here because the contract knows the treasury only by its hash and cannot measure the
/// script; `sdk/test/treasury-floor.test.ts` measures the real lock and fails if this
/// number stops matching it.
pub const TREASURY_MIN_SHANNONS: u64 = 63 * 100_000_000;

/// The most of a sale the protocol will ever take, in percent, which is what decides
/// where the flat-cell band starts: below `TREASURY_MIN_SHANNONS * 100 / this`, a whole
/// cell would be a larger share than this and nothing is charged at all.
pub const SALE_FEE_MAX_PERCENT: u64 = 10;

/// What the treasury is owed on a sale at `price`, and by subtraction what the
/// seller is owed. Divides before it multiplies, so the rounding goes to the seller
/// and the arithmetic cannot overflow.
///
/// **One percent, or a whole cell, or nothing.** The protocol's share has to exist as an
/// output, and a cell cannot hold less than its own bytes, so one percent of a small sale
/// is not a small fee, it is an impossible one. Three bands follow from that and there is
/// no fourth:
///
/// * at or above 6,300 CKB, one percent, which is at least a cell;
/// * from 630 to 6,300, a flat cell, 63 CKB, which is between 1% and 10% of the price;
/// * below 630, nothing, because a cell would be more than a tenth and no rate we would
///   defend charges that.
///
/// The effective rate therefore tapers from ten percent at the bottom to one at the top,
/// and every sale anybody would call a sale pays something. The alternative shapes were
/// weighed with figures in RULES.md: a flat rate has a floor too (at ten percent it is
/// 630 CKB), because no rate removes the chain's minimum, it only moves it.
///
/// It cannot be gamed by under-pricing: the fee is a fraction of what the seller actually
/// receives, so anybody who lists low to avoid it gives up more than it. Two steps remain,
/// at 630 and at nothing below it, and a step is what a floor is.
pub const fn sale_fee(price: u64) -> u64 {
    let one_percent = (price / 100).saturating_mul(SALE_FEE_PERCENT);
    if one_percent >= TREASURY_MIN_SHANNONS {
        // The ordinary case: the rate is the rate.
        one_percent
    } else if price >= TREASURY_MIN_SHANNONS.saturating_mul(100 / SALE_FEE_MAX_PERCENT) {
        // One percent of this would be too small to be a cell, but a whole cell is still
        // a defensible share of it, so the floor is charged instead.
        TREASURY_MIN_SHANNONS
    } else {
        // And below that, nothing: a cell's worth of fee on a sale this size would be a
        // larger share than any rate we would defend.
        0
    }
}

/// The band decision 0009 fixed for the five-plus line, in CKB per year: a tenfold
/// move in either direction.
///
/// Read the correction in that decision before trusting these: they are asserted in
/// the test suite and checked in review, and they are **not** enforced against an
/// upgrade, which replaces this code and these bounds in the same transaction. A
/// bound written beside the number it guards cannot bind the one party able to
/// change the number. Enforcing it needs a bespoke lock on the code cell, which is
/// the same lock the upgrade delay would need, and is not built.
pub const FEE_BAND_MIN_CKB: u64 = 500;
pub const FEE_BAND_MAX_CKB: u64 = 50_000;

// --- Commit-reveal (anti front-running, decision 0004) ---------------------

/// Length of the reveal secret (bytes). High-entropy, chosen by the registrant at
/// commit time and revealed only in the register tx.
pub const SECRET_LEN: usize = 32;

/// Minimum age (seconds) a CommitCell must have before its `register`/reveal.
/// Enforced on-chain by requiring the spent CommitCell's input `since` to be a
/// **relative-timestamp** `>= COMMIT_MIN_DELAY`, CKB consensus then refuses to mine
/// the reveal until the commit is genuinely this old, so a mempool watcher cannot
/// produce a matured commit for a just-revealed label in time to front-run it.
pub const COMMIT_MIN_DELAY: u64 = 60;

/// The commitment stored (as the cell's whole `data`) in a CommitCell:
/// `blake2b(namespace_id ‖ label ‖ owner_lock_hash ‖ secret)`.
///
/// It hides the label (so it can't be copied before reveal) and binds the
/// `owner_lock_hash` (so a front-runner can't reuse someone else's commitment,
/// the revealed name would still go to the committed owner) and the `namespace_id`
/// (so a commit can't be replayed against a different account-cell-type instance).
/// The single source of truth, the contract, SDK, registrar and scripts all
/// reproduce these exact bytes.
/// Plain concatenation, no length prefixes. That is unambiguous only because every
/// field after the variable-length label is fixed-size, so two different inputs can
/// never serialise to the same bytes. Adding a second variable-length field here
/// would silently break that, and would have to bring a length prefix with it.
pub fn commitment(
    namespace_id: &[u8; NAMESPACE_LEN],
    label: &[u8],
    owner_lock_hash: &[u8; OWNER_HASH_LEN],
    secret: &[u8; SECRET_LEN],
) -> [u8; 32] {
    let mut buf = Vec::with_capacity(NAMESPACE_LEN + label.len() + OWNER_HASH_LEN + SECRET_LEN);
    buf.extend_from_slice(namespace_id);
    buf.extend_from_slice(label);
    buf.extend_from_slice(owner_lock_hash);
    buf.extend_from_slice(secret);
    ckb_blake2b256(&buf)
}

/// Validate a registrable label: 1..=40 chars, charset `[a-z0-9-]`, and no
/// leading/trailing hyphen. Enforced on-chain (so a hand-crafted tx can't squat
/// oversized or confusable names) and mirrored off-chain. The root (empty label)
/// is exempt and never passed here.
pub fn validate_label(label: &[u8]) -> Result<(), Error> {
    let n = label.len();
    if n == 0 || n > MAX_LABEL_LEN {
        return Err(Error::InvalidLength);
    }
    // A label is one or two dot-separated parts (decision 0008). Every part obeys
    // the original rule, so a plain name is just the one-part case and nothing that
    // validated before stops validating now.
    //
    // **One level of nesting, and only one.** `shop.telmo` is a name;
    // `a.shop.telmo` is not. Nesting composes naturally in the code (parent_label
    // strips one level at a time), which is exactly why it has to be stopped
    // deliberately: every level is another cell paying its own rent, another expiry
    // that must sit inside its parent's, and another thing to explain. Depth beyond
    // one buys nobody anything and costs everybody clarity.
    // Parts first, depth second, so malformed input gets the precise complaint:
    // `a..b` is two dots AND an empty part, and "invalid characters" is far more
    // use to whoever typed it than "too deep".
    for part in label.split(|&b| b == b'.') {
        validate_label_part(part)?;
    }
    if label.iter().filter(|&&b| b == b'.').count() > MAX_LABEL_DEPTH - 1 {
        return Err(Error::TooDeep);
    }
    Ok(())
}

/// How many dot-separated parts a name may have: `telmo` or `shop.telmo`, no more.
pub const MAX_LABEL_DEPTH: usize = 2;

/// One dot-separated part: 1..=MAX_LABEL_LEN of `[a-z0-9-]`, no leading/trailing hyphen.
fn validate_label_part(part: &[u8]) -> Result<(), Error> {
    let n = part.len();
    if n == 0 {
        // empty part == leading/trailing dot, or `..`
        return Err(Error::InvalidCharset);
    }
    for (i, &b) in part.iter().enumerate() {
        let is_charset = b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-';
        if !is_charset {
            return Err(Error::InvalidCharset);
        }
        if b == b'-' && (i == 0 || i == n - 1) {
            return Err(Error::InvalidCharset); // no leading/trailing hyphen
        }
    }
    Ok(())
}

/// The parent of a sub-name: everything after the FIRST dot. `None` for a plain name.
///
/// `loja.telmo` → `telmo`, and `a.b.telmo` → `b.telmo`, so nesting composes: each
/// level only ever has to authorize the level directly below it.
pub fn parent_label(label: &[u8]) -> Option<&[u8]> {
    label
        .iter()
        .position(|&b| b == b'.')
        .map(|i| &label[i + 1..])
}

/// Build an AccountCell `data` blob (fixed header + label) from a precomputed
/// witness hash. Off-chain / test helper, the on-chain script only reads. There is
/// no id argument: the id is the label's, and the root's is the empty label's.
///
/// Panics on an expiry the five-byte field cannot hold; a caller wanting the far
/// future has misunderstood the ten-year term cap, not run out of bytes.
pub fn build_account_data(
    witness_hash: &[u8; 32],
    next: &Id,
    expired_at: u64,
    owner_lock_hash: &[u8; OWNER_HASH_LEN],
    manager_lock_hash: &[u8; OWNER_HASH_LEN],
    label: &[u8],
) -> Vec<u8> {
    assert!(expired_at <= MAX_EXPIRED_AT, "expired_at does not fit in five bytes");
    let mut d = Vec::with_capacity(DATA_HEADER_LEN + label.len());
    d.push(VERSION_V3);
    d.extend_from_slice(witness_hash);
    d.extend_from_slice(next);
    d.extend_from_slice(&expired_at.to_le_bytes()[..EXPIRY_LEN]);
    d.extend_from_slice(owner_lock_hash);
    d.extend_from_slice(manager_lock_hash);
    d.extend_from_slice(label);
    d
}

/// Build an AccountCell from a decoded witness: returns `(data, witness_bytes)`,
/// with the witness hash in the data being `blake2b(witness_bytes)`. An undelegated
/// name passes its owner as the manager too.
pub fn build_account(
    witness: &WitnessData,
    next: &Id,
    expired_at: u64,
    owner_lock_hash: &[u8; OWNER_HASH_LEN],
    manager_lock_hash: &[u8; OWNER_HASH_LEN],
    label: &[u8],
) -> (Vec<u8>, Vec<u8>) {
    let payload = witness.encode();
    let wh = ckb_blake2b256(&payload);
    (
        build_account_data(
            &wh,
            next,
            expired_at,
            owner_lock_hash,
            manager_lock_hash,
            label,
        ),
        payload,
    )
}

/// Error codes returned by the on-chain scripts (mapped to a process exit `i8`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i8)]
pub enum Error {
    IndexOutOfBound = 1,
    ItemMissing = 2,
    LengthNotEnough = 3,
    Encoding = 4,
    // --- protocol ---
    MalformedAccountData = 20,
    WitnessHashMismatch = 21,
    AccountIdMismatch = 22,
    UnknownAction = 23,
    NotInPredecessorRange = 24, // register: x not strictly inside (p.id, p.next)
    LinkedListBroken = 25,      //      next pointers not rewired correctly
    DuplicateId = 26,
    StructuralDrift = 27, //       a field changed that the action does not permit
    NotExpired = 28,      //            recycle on a non-expired account
    Unauthorized = 29,
    InvalidCharset = 30,
    InvalidLength = 31,
    InsufficientPrice = 35, // register: new cell locks less than price_floor(len)
    SequencerUnauthorized = 32, // register without a sequencer-locked input
    ConfigCellMissing = 33, //     register without (or with a malformed) ConfigCell dep
    GenesisSeedMissing = 34, //    genesis without consuming the one-time genesis-seed cell
    CommitMissing = 36,     //         register without a matching CommitCell input (commit-reveal)
    CommitTooYoung = 37, //        the CommitCell's since is not a relative-timestamp >= MIN_DELAY
    NullOwner = 38, //             register/transfer with an all-zero owner_lock_hash (would be unspendable)
    ExpiryTooSoon = 39, //         register for less than MIN_TERM_YEARS (also covers L-2)
    ParentMissing = 40, //         register of a sub-name without its parent as a cell dep (0008)
    ParentOutlived = 41, //        a sub-name may not expire later than its parent (0008)
    TreasuryUnpaid = 42, //        register/renew without paying registration_fee to the treasury (0009)
    TermTooLong = 43,    //           register/renew for more than MAX_TERM_YEARS at once (0009)
    OwnerIsCellLock = 44, //       owner/manager set to the AccountCell's own always-success lock
    TooDeep = 45,        //               more than MAX_LABEL_DEPTH dot-separated parts
    RootNotRecyclable = 46, //     the root sentinel's id may never be recycled or registered
    CommitNotOwned = 47, //        the CommitCell is not held by the owner it commits to
    CellLockNotAccountLock = 48, // an output AccountCell wears a lock other than the account-lock its inputs wear
}

/// The lock hash the registration fee must be paid to (decision 0009).
///
/// Deliberately **not** the upgrade wallet: `cells-watchtower` alerts on funds
/// arriving there, and a fee on every registration would bury the one alert that
/// matters under routine noise.
///
/// On testnet this is the JoyID account (the owner of `tecmeup.cell`), which has no
/// seed to lose. Before mainnet it has to be a deliberate choice rather than an
/// inherited default.
///
/// `CELLS_TREASURY_LOCK_HASH` overrides it at **compile time** (64 hex characters, no
/// `0x`). The integration tests need this: a lock hash is derived from the lock's own
/// code and args, so a mock VM cannot conjure a cell whose lock hashes to the address
/// above, and without an override the fee check could only ever be tested failing.
/// `make test` builds a separate binary with the harness's own hash and runs against
/// that; it never overwrites the deployable artifact.
pub const TREASURY_LOCK_HASH: [u8; 32] =
    parse_lock_hash(match option_env!("CELLS_TREASURY_LOCK_HASH") {
        Some(s) => s,
        None => "d9d177037d0888e09330bf0dd18e98c534ea3479b4376911d0a5279ead21e0f8",
    });

/// The `sale-lock`'s **code** hash, so `account-cell-type` can recognise an offer being
/// spent in the same transaction and add what that sale owes on top of its own fee.
///
/// This is the coupling F-9 costs, and the reason it is safe to bake a number: the sale
/// lock is upgraded **in place by type id**, so its code hash does not move. Three
/// upgrades on 2026-09-14 all printed `sale.codeHash unchanged`. If that ever stops being
/// true, this constant goes stale and the guard fails **open**, which is why
/// `verify-onchain.mjs` compares it against the deployment and a test compares it against
/// `deployment.json`. Overridable at compile time for the same reason the treasury hash is.
///
/// A namespace deployed without a sale lock leaves this at all zeros, which no real lock
/// can hash to, so nothing is ever recognised and nothing is added.
pub const SALE_LOCK_CODE_HASH: [u8; 32] =
    parse_lock_hash(match option_env!("CELLS_SALE_LOCK_CODE_HASH") {
        Some(s) => s,
        None => "498ab6b49b6b25b3c47fcea74bd8a4447bc4efda6417809152a846e058ad0ae4",
    });

/// Bytes of a sale lock's args: the seller's 32-byte lock hash, then the price.
pub const SALE_ARGS_LEN: usize = 40;

const fn parse_lock_hash(s: &str) -> [u8; 32] {
    let b = s.as_bytes();
    assert!(
        b.len() == 64,
        "a compile-time hash must be 64 hex characters, without a 0x prefix"
    );
    let mut out = [0u8; 32];
    let mut i = 0;
    while i < 32 {
        out[i] = nibble(b[i * 2]) * 16 + nibble(b[i * 2 + 1]);
        i += 1;
    }
    out
}

const fn nibble(c: u8) -> u8 {
    match c {
        b'0'..=b'9' => c - b'0',
        b'a'..=b'f' => c - b'a' + 10,
        b'A'..=b'F' => c - b'A' + 10,
        _ => panic!("a compile-time hash must be hexadecimal"),
    }
}

// --- The price tag (decision 0014) ---------------------------------------------
//
// The registration fee above is a ceiling. One on-chain "price cell", found by the
// type-script hash below, may discount it by a factor in basis points, and may never
// raise it. `account-cell-type` reads that cell as a dep; when the dep is absent,
// malformed or out of range the factor is `PRICE_FACTOR_MAX`, the full price, so
// every failure costs the payer and never the treasury. How the factor may change is
// the business of the cell's own type script, `price-cell-type`.

/// The price cell's type-script hash, compiled in the way the treasury is. All zeros
/// means "there is no price cell" and the schedule applies unchanged.
pub const PRICE_CELL_TYPE_HASH: [u8; 32] =
    parse_lock_hash(match option_env!("CELLS_PRICE_CELL_TYPE_HASH") {
        Some(s) => s,
        None => "6b3a6afbdbfd73f604372c57417bcfe66fb297375ed127052746696b6b7fa6bc",
    });

/// Price cell data: `version (1) ‖ factor (4, little-endian, basis points)`.
pub const PRICE_DATA_VERSION: u8 = 1;
pub const PRICE_DATA_LEN: usize = 5;
/// No discount: the schedule as written.
pub const PRICE_FACTOR_MAX: u32 = 10_000;
/// 63 CKB on the 5+ line. The treasury is a JoyID lock with 22-byte args, so the
/// smallest output it can hold is 8 + 33 + 22 = 63 CKB; below that the fee output is
/// unconstructible and registration bricks itself (0014). 5 000 CKB x 126 / 10 000.
pub const PRICE_FACTOR_MIN: u32 = 126;
/// A price cell may change at most once every six hours, enforced by `since` on its
/// input. It was a day, with a quarter per move; six hours with a sixteenth per move
/// keeps the same ceiling on what a stolen key can do before a person wakes up (about
/// a quarter a day, spread over four moves) while letting an honest keeper follow the
/// coin four times as often. The two numbers are a pair: shorten one without
/// shrinking the other and the ceiling goes.
pub const PRICE_COOLDOWN_SECS: u64 = 21_600;

/// `Some(bps)` iff the data is well formed and the factor is inside the band.
pub fn parse_price_factor(data: &[u8]) -> Option<u32> {
    if data.len() != PRICE_DATA_LEN || data[0] != PRICE_DATA_VERSION {
        return None;
    }
    let bps = u32::from_le_bytes([data[1], data[2], data[3], data[4]]);
    if !(PRICE_FACTOR_MIN..=PRICE_FACTOR_MAX).contains(&bps) {
        return None;
    }
    Some(bps)
}

/// Encode a factor as price cell data.
pub fn price_data(bps: u32) -> [u8; PRICE_DATA_LEN] {
    let b = bps.to_le_bytes();
    [PRICE_DATA_VERSION, b[0], b[1], b[2], b[3]]
}

/// A fee in shannons after the factor, rounding down. A factor above the maximum is
/// treated as the maximum: this can only ever lower the fee.
pub fn apply_price_factor(fee: u64, bps: u32) -> u64 {
    let bps = if bps > PRICE_FACTOR_MAX { PRICE_FACTOR_MAX } else { bps };
    ((fee as u128 * bps as u128) / PRICE_FACTOR_MAX as u128) as u64
}

/// Within a sixteenth either way: `new * 16` inside `[old * 15, old * 17]`.
pub fn price_step_ok(old: u32, new: u32) -> bool {
    let (o, n) = (old as u64, new as u64);
    n * 16 >= o * 15 && n * 16 <= o * 17
}

// The old MIN_REGISTRATION_TERM (one day) lived here. It was the whole of the term
// rule, which is why `register` defaulted to the year 2096 and nothing ever came up
// for renewal. `MIN_TERM_YEARS` replaced it (decision 0009), and a term of at least a
// year subsumes what that check was for: a name that has not already expired
// (SECURITY.md L-2).

/// The protocol action a transaction declares (see SPEC §6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    Register,
    EditRecords,
    EditManager,
    Transfer,
    Renew,
    Recycle,
}

impl Action {
    /// Parse the ascii action name carried in `ActionData.action`.
    pub fn from_bytes(b: &[u8]) -> Result<Self, Error> {
        match b {
            b"register" => Ok(Action::Register),
            b"edit_records" => Ok(Action::EditRecords),
            b"edit_manager" => Ok(Action::EditManager),
            b"transfer" => Ok(Action::Transfer),
            b"renew" => Ok(Action::Renew),
            b"recycle" => Ok(Action::Recycle),
            _ => Err(Error::UnknownAction),
        }
    }
}

/// Zero-copy reader over an `AccountCell.data` byte slice.
#[derive(Clone, Copy)]
pub struct AccountData<'a>(&'a [u8]);

impl<'a> AccountData<'a> {
    pub fn parse(data: &'a [u8]) -> Result<Self, Error> {
        if data.len() < DATA_HEADER_LEN || data[OFF_VERSION] != VERSION_V3 {
            return Err(Error::MalformedAccountData);
        }
        Ok(AccountData(data))
    }

    pub fn witness_hash(&self) -> &'a [u8] {
        &self.0[OFF_WITNESS_HASH..OFF_NEXT]
    }

    /// The id is not stored: it is the label's, `blake2b(label)[..20]`, and the root
    /// sentinel, whose label is empty, is `ROOT_ID` by definition. `blake2b("")` is
    /// not zero, so the root must be special-cased here and not by hashing.
    pub fn id(&self) -> Id {
        let label = self.account();
        if label.is_empty() {
            ROOT_ID
        } else {
            account_id(label)
        }
    }

    pub fn next(&self) -> Id {
        let mut n = [0u8; ID_LEN];
        n.copy_from_slice(&self.0[OFF_NEXT..OFF_EXPIRED_AT]);
        n
    }

    pub fn expired_at(&self) -> u64 {
        let mut buf = [0u8; 8];
        buf[..EXPIRY_LEN].copy_from_slice(&self.0[OFF_EXPIRED_AT..OFF_OWNER]);
        u64::from_le_bytes(buf)
    }

    /// The owner's identity: the first twenty bytes of a lock-script hash. An owner
    /// action (edit / transfer) requires the tx to spend a cell under a lock whose
    /// hash begins with these bytes.
    pub fn owner_lock_hash(&self) -> &'a [u8] {
        &self.0[OFF_OWNER..OFF_MANAGER]
    }

    /// The manager's identity, same shape; may edit records but not transfer or
    /// re-delegate. Equal to the owner when the name is not delegated.
    pub fn manager_lock_hash(&self) -> &'a [u8] {
        &self.0[OFF_MANAGER..OFF_ACCOUNT]
    }

    /// The label bytes (e.g. `b"alice"`), without the `.cell` suffix.
    pub fn account(&self) -> &'a [u8] {
        &self.0[OFF_ACCOUNT..]
    }

    /// Is the name delegated to someone other than its owner?
    pub fn is_delegated(&self) -> bool {
        self.owner_lock_hash() != self.manager_lock_hash()
    }
}

// --- The linked-list invariant (SPEC §3) -----------------------------------

/// Does the predecessor range `(lo, hi]` (half-open, wraparound-aware) contain
/// `id`? `lo == p.id`, `hi == p.next`. Used for membership / recycle.
///
/// The list is circular: when `lo >= hi` the node wraps past the top of the id
/// space (and the root node `lo == hi` covers everything).
pub fn covers(lo: &Id, hi: &Id, id: &Id) -> bool {
    if lo < hi {
        lo < id && id <= hi
    } else {
        id > lo || id <= hi
    }
}

/// Can a *new* id be inserted into predecessor `p`? Requires `id` strictly
/// between `(p.id, p.next)` (open), wraparound-aware. Equality is rejected, that
/// would be a duplicate name (SPEC §3.1).
pub fn between(lo: &Id, hi: &Id, id: &Id) -> bool {
    if lo < hi {
        lo < id && id < hi
    } else {
        // wraparound / root: anything except the endpoints themselves
        (id > lo || id < hi) && id != lo && id != hi
    }
}

// --- AccountCellWitness payload (SPEC §2.2) --------------------------------
//
// The off-chain payload hashed into `AccountCell.data[0..32]`. Phase 2 carries
// only resolution records here, the owner identity moved into the authenticated
// `data` header (`owner_lock_hash`), so a witness edit can never change who owns
// the name. Compact, self-describing encoding (not molecule); `schemas/cells.mol`
// is the eventual wire format. Length prefixes: key/label are u8-bounded (<=255),
// value is u16-bounded (<=65535).

/// A signature-scheme id + address/pubkey-hash payload. Retained for off-chain
/// callers that describe a key; the on-chain owner identity is a lock hash.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RoleKey {
    pub algorithm_id: u8,
    pub payload: Vec<u8>,
}

/// A resolution record (`key` is the dotted key, e.g. `address.60`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordEntry {
    pub key: Vec<u8>,
    pub label: Vec<u8>,
    pub value: Vec<u8>,
    pub ttl: u32,
}

/// The decoded AccountCell witness payload (resolution records).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct WitnessData {
    pub records: Vec<RecordEntry>,
}

impl WitnessData {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&(self.records.len() as u16).to_le_bytes());
        for r in &self.records {
            push_u8_len(&mut out, &r.key);
            push_u8_len(&mut out, &r.label);
            push_u16_len(&mut out, &r.value);
            out.extend_from_slice(&r.ttl.to_le_bytes());
        }
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<WitnessData, Error> {
        let mut b = bytes;
        let n = read_u16(&mut b)? as usize;
        let mut records = Vec::with_capacity(n);
        for _ in 0..n {
            let key = read_u8_len(&mut b)?;
            let label = read_u8_len(&mut b)?;
            let value = read_u16_len(&mut b)?;
            let ttl = read_u32(&mut b)?;
            records.push(RecordEntry {
                key,
                label,
                value,
                ttl,
            });
        }
        if !b.is_empty() {
            return Err(Error::Encoding); // trailing garbage
        }
        Ok(WitnessData { records })
    }
}

/// Length-prefixed byte strings. These do NOT refuse an oversized field yet (F-10, open):
/// the `debug_assert!` is compiled out of the build that ships, and release clamps the
/// prefix while writing every byte, so the decoder refuses the whole set with `Encoding`.
/// It fails closed and nothing on chain calls this. The TypeScript `pushBytes` refuses at
/// write time; make these return `Result` the next time `cells-core` changes for real.
fn push_u8_len(out: &mut Vec<u8>, b: &[u8]) {
    debug_assert!(b.len() <= u8::MAX as usize, "cells: {} bytes exceeds a 1-byte length prefix", b.len());
    out.push(b.len().min(u8::MAX as usize) as u8);
    out.extend_from_slice(b);
}
fn push_u16_len(out: &mut Vec<u8>, b: &[u8]) {
    debug_assert!(b.len() <= u16::MAX as usize, "cells: {} bytes exceeds a 2-byte length prefix", b.len());
    out.extend_from_slice(&(b.len().min(u16::MAX as usize) as u16).to_le_bytes());
    out.extend_from_slice(b);
}
fn read_u8(b: &mut &[u8]) -> Result<u8, Error> {
    let (h, t) = b.split_first().ok_or(Error::Encoding)?;
    *b = t;
    Ok(*h)
}
fn read_u16(b: &mut &[u8]) -> Result<u16, Error> {
    if b.len() < 2 {
        return Err(Error::Encoding);
    }
    let v = u16::from_le_bytes([b[0], b[1]]);
    *b = &b[2..];
    Ok(v)
}
fn read_u32(b: &mut &[u8]) -> Result<u32, Error> {
    if b.len() < 4 {
        return Err(Error::Encoding);
    }
    let v = u32::from_le_bytes([b[0], b[1], b[2], b[3]]);
    *b = &b[4..];
    Ok(v)
}
fn read_u8_len(b: &mut &[u8]) -> Result<Vec<u8>, Error> {
    let n = read_u8(b)? as usize;
    if b.len() < n {
        return Err(Error::Encoding);
    }
    let v = b[..n].to_vec();
    *b = &b[n..];
    Ok(v)
}
fn read_u16_len(b: &mut &[u8]) -> Result<Vec<u8>, Error> {
    let n = read_u16(b)? as usize;
    if b.len() < n {
        return Err(Error::Encoding);
    }
    let v = b[..n].to_vec();
    *b = &b[n..];
    Ok(v)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(n: u8) -> Id {
        let mut x = [0u8; ID_LEN];
        x[ID_LEN - 1] = n;
        x
    }

    #[test]
    fn covers_normal_range() {
        // p covers (10, 20]
        assert!(!covers(&id(10), &id(20), &id(10))); // lower bound excluded
        assert!(covers(&id(10), &id(20), &id(11)));
        assert!(covers(&id(10), &id(20), &id(20))); // upper bound included
        assert!(!covers(&id(10), &id(20), &id(21)));
        assert!(!covers(&id(10), &id(20), &id(5)));
    }

    #[test]
    fn covers_wraparound_node() {
        // p wraps: covers (200, 5]
        assert!(covers(&id(200), &id(5), &id(255)));
        assert!(covers(&id(200), &id(5), &id(5)));
        assert!(!covers(&id(200), &id(5), &id(6)));
        assert!(!covers(&id(200), &id(5), &id(200)));
    }

    #[test]
    fn root_covers_everything() {
        let zero = id(0);
        assert!(covers(&zero, &zero, &id(1)));
        assert!(covers(&zero, &zero, &id(255)));
    }

    #[test]
    fn between_rejects_endpoints() {
        assert!(!between(&id(10), &id(20), &id(10)));
        assert!(!between(&id(10), &id(20), &id(20)));
        assert!(between(&id(10), &id(20), &id(15)));
    }

    #[test]
    fn between_wraparound() {
        assert!(between(&id(200), &id(5), &id(255)));
        assert!(between(&id(200), &id(5), &id(2)));
        assert!(!between(&id(200), &id(5), &id(5)));
        assert!(!between(&id(200), &id(5), &id(200)));
        assert!(!between(&id(200), &id(5), &id(100))); // outside the wrap
    }

    #[test]
    fn parse_rejects_short_data() {
        assert_eq!(
            AccountData::parse(&[0u8; 10]).err(),
            Some(Error::MalformedAccountData)
        );
    }

    #[test]
    fn parse_reads_fields() {
        let mut data = [0u8; DATA_HEADER_LEN + 5];
        data[OFF_VERSION] = VERSION_V3;
        data[OFF_NEXT + ID_LEN - 1] = 0x22; // next = ..0x22
        data[OFF_EXPIRED_AT..OFF_OWNER].copy_from_slice(&1_700_000_000u64.to_le_bytes()[..EXPIRY_LEN]);
        data[OFF_OWNER..OFF_MANAGER].copy_from_slice(&[0xab; OWNER_HASH_LEN]);
        data[OFF_MANAGER..OFF_ACCOUNT].copy_from_slice(&[0xcd; OWNER_HASH_LEN]);
        data[OFF_ACCOUNT..].copy_from_slice(b"alice");

        let a = AccountData::parse(&data).unwrap();
        assert_eq!(a.id(), account_id(b"alice")); // derived from the label, not stored
        assert_eq!(a.next(), id(0x22));
        assert_eq!(a.expired_at(), 1_700_000_000);
        assert_eq!(a.owner_lock_hash(), &[0xab; OWNER_HASH_LEN]);
        assert_eq!(a.manager_lock_hash(), &[0xcd; OWNER_HASH_LEN]);
        assert!(a.is_delegated());
        assert_eq!(a.account(), b"alice");

        // Any other version byte is not a cell of this layout.
        data[OFF_VERSION] = 0x02;
        assert_eq!(AccountData::parse(&data).err(), Some(Error::MalformedAccountData));
        // And a cell shorter than the header is not one either.
        assert!(AccountData::parse(&data[..DATA_HEADER_LEN - 1]).is_err());
    }

    #[test]
    fn label_validation() {
        assert!(validate_label(b"alice").is_ok());
        assert!(validate_label(b"a").is_ok());
        assert!(validate_label(b"a-b-1").is_ok());
        assert!(validate_label(&[b'a'; MAX_LABEL_LEN]).is_ok());
        // length
        assert_eq!(validate_label(b"").err(), Some(Error::InvalidLength));
        assert_eq!(
            validate_label(&[b'a'; MAX_LABEL_LEN + 1]).err(),
            Some(Error::InvalidLength)
        );
        // charset
        assert_eq!(validate_label(b"Alice").err(), Some(Error::InvalidCharset)); // uppercase
        assert_eq!(
            validate_label("naïve".as_bytes()).err(),
            Some(Error::InvalidCharset)
        ); // non-ascii
        assert_eq!(validate_label(b"a b").err(), Some(Error::InvalidCharset));
        // edge hyphens
        assert_eq!(validate_label(b"-ab").err(), Some(Error::InvalidCharset));
        assert_eq!(validate_label(b"ab-").err(), Some(Error::InvalidCharset));
        assert_eq!(validate_label(b"-").err(), Some(Error::InvalidCharset));
    }

    #[test]
    fn sub_name_labels() {
        // dotted labels are valid (decision 0008), each part obeys the old rule
        assert!(validate_label(b"shop.telmo").is_ok());
        // `a.b.telmo` used to be valid here. Nesting is now capped at one level,
        // a deliberate behaviour change and not a regression, so it moved to
        // `nesting_stops_at_one_level`.
        assert!(validate_label(b"my-shop.telmo").is_ok());
        // an empty part is a leading/trailing dot or `..`
        assert_eq!(validate_label(b".telmo").err(), Some(Error::InvalidCharset));
        assert_eq!(validate_label(b"telmo.").err(), Some(Error::InvalidCharset));
        assert_eq!(validate_label(b"a..b").err(), Some(Error::InvalidCharset));
        // the per-part rules still bite inside a sub-name
        assert_eq!(
            validate_label(b"-shop.telmo").err(),
            Some(Error::InvalidCharset)
        );
        assert_eq!(
            validate_label(b"shop-.telmo").err(),
            Some(Error::InvalidCharset)
        );
        assert_eq!(
            validate_label(b"Shop.telmo").err(),
            Some(Error::InvalidCharset)
        );
        // the total length cap is unchanged
        assert_eq!(
            validate_label(&[b'a'; MAX_LABEL_LEN + 1]).err(),
            Some(Error::InvalidLength)
        );
    }

    #[test]
    fn parent_of_a_sub_name() {
        assert_eq!(parent_label(b"shop.telmo"), Some(&b"telmo"[..]));
        // parent_label itself peels one level from anything, including a label that
        // validate_label now refuses. Keeping the two separate is deliberate: the
        // depth rule lives in one place, not smeared across every helper.
        assert_eq!(parent_label(b"a.b.telmo"), Some(&b"b.telmo"[..]));
        assert_eq!(parent_label(b"telmo"), None); // a plain name has no parent
    }

    #[test]
    fn pricing_curve() {
        let ckb = 100_000_000u64;
        // Flat: the rent is refundable, so a graduated deposit deterred nothing.
        for n in [1usize, 2, 3, 4, 5, 32, 33, MAX_LABEL_LEN] {
            assert_eq!(price_floor(n), 240 * ckb, "the floor is flat, at {n} characters");
        }
        // And it must clear CKB's own minimum at every length and in BOTH layouts, or
        // the contract accepts a cell consensus then refuses. The old schedule failed
        // this from 33 characters up, and for every v2 name of five or more.
        for n in 1..=MAX_LABEL_LEN {
            // One layout now: capacity field, the account-lock (no args), the type
            // script with its 20-byte namespace args, the header, the label.
            let occupied = 8 + (32 + 1) + (32 + 1 + NAMESPACE_LEN) + DATA_HEADER_LEN + n;
            assert!(
                price_floor(n) >= (occupied as u64) * ckb,
                "floor under CKB's own minimum at {n} characters ({occupied} CKB)"
            );
        }
        // The fee still carries the anti-squatting job, and still slopes.
        assert!(registration_fee(b"a", 1) > registration_fee(b"ab", 1));
        assert!(registration_fee(b"ab", 1) > registration_fee(b"telmo", 1));
    }

    #[test]
    fn nesting_stops_at_one_level() {
        assert!(validate_label(b"telmo").is_ok());
        assert!(validate_label(b"shop.telmo").is_ok());
        // Two dots is a sub-name of a sub-name, which the protocol does not do.
        assert!(matches!(
            validate_label(b"a.shop.telmo"),
            Err(Error::TooDeep)
        ));
        assert!(matches!(validate_label(b"a.b.c.d"), Err(Error::TooDeep)));
        // parent_label still peels exactly one level, which is now all there is.
        assert_eq!(parent_label(b"shop.telmo"), Some(&b"telmo"[..]));
        assert_eq!(parent_label(b"telmo"), None);
    }

    #[test]
    fn ten_years_are_charged_as_eight() {
        // The headline: a full term is a fifth off.
        assert_eq!(charged_years(10), 8);
        assert_eq!(registration_fee(b"telmo", 10), 8 * registration_fee(b"telmo", 1));

        // One free year per five bought, and nothing free below that.
        assert_eq!(
            (1..=10).map(charged_years).collect::<Vec<_>>(),
            vec![1, 2, 3, 4, 4, 5, 6, 7, 8, 8]
        );

        // The discount is proportional, so it does not favour long names over short.
        for label in [&b"a"[..], b"ab", b"abc", b"acme", b"telmo"] {
            assert_eq!(registration_fee(label, 10), 8 * registration_fee(label, 1));
        }

        // A term buys at least as much time for the money as any shorter one: the
        // price per year never rises with the term.
        for years in 2..=10u64 {
            let per_year = registration_fee(b"telmo", years) / years;
            let one = registration_fee(b"telmo", 1);
            assert!(per_year <= one, "{years} years cost more per year than one");
        }
    }

    #[test]
    fn a_child_costs_a_fifth_of_its_parent() {
        // Priced from the parent, divided by five, at every band and every term.
        for (parent, child) in [
            (&b"telmo"[..], &b"shop.telmo"[..]),
            (b"acme", b"alice.acme"),
            (b"abc", b"x.abc"),
            (b"ab", b"x.ab"),
            (b"a", b"x.a"),
        ] {
            for years in [1u64, 3, 10] {
                assert_eq!(
                    registration_fee(child, years),
                    registration_fee(parent, years) / 5,
                    "{} against {}",
                    core::str::from_utf8(child).unwrap(),
                    core::str::from_utf8(parent).unwrap()
                );
            }
        }

        // The child's own length buys nothing: what it costs is its parent's business.
        assert_eq!(registration_fee(b"a.telmo", 1), registration_fee(b"warehouse.telmo", 1));

        // A short parent still makes dearer children than a long one, so a namespace
        // is worth what its root is worth.
        assert!(registration_fee(b"x.a", 1) > registration_fee(b"x.telmo", 1));

        // And the exact figures, since these are the numbers a price list quotes.
        let ckb = 100_000_000u64;
        assert_eq!(registration_fee(b"shop.telmo", 1), 1_000 * ckb);
        assert_eq!(registration_fee(b"alice.acme", 1), 4_000 * ckb);
        assert_eq!(registration_fee(b"shop.telmo", 10), 8_000 * ckb);
    }

    #[test]
    fn registration_fee_is_per_year_and_inside_the_band() {
        let ckb = 100_000_000u64;
        assert_eq!(registration_fee(b"telmo", 1), 5_000 * ckb);
        assert_eq!(registration_fee(&[b'a'; 40], 1), 5_000 * ckb); // long names all cost the same
        assert_eq!(registration_fee(b"acme", 1), 20_000 * ckb);
        assert_eq!(registration_fee(b"abc", 1), 80_000 * ckb);
        assert_eq!(registration_fee(b"ab", 1), 200_000 * ckb);
        assert_eq!(registration_fee(b"a", 1), 500_000 * ckb);

        // Whole years, priced linearly until the free year: four years cost four.
        assert_eq!(registration_fee(b"telmo", 4), 4 * registration_fee(b"telmo", 1));

        // Shorter is always dearer, at every term.
        for years in [1, 3, 10] {
            assert!(registration_fee(b"a", years) > registration_fee(b"ab", years));
            assert!(registration_fee(b"ab", years) > registration_fee(b"abc", years));
            assert!(registration_fee(b"abc", years) > registration_fee(b"acme", years));
            assert!(registration_fee(b"acme", years) > registration_fee(b"telmo", years));
        }

        // An empty label is rejected by the charset check long before this, but if it
        // ever reached here it must not be free.
        assert_eq!(registration_fee(b"", 1), u64::MAX);

        // The band from decision 0009. This is a tripwire on the constant above, not
        // a guarantee: an upgrade replaces the fee and this bound together. Read the
        // correction in that decision before quoting it as protection.
        let per_year = registration_fee(b"telmo", 1) / ckb;
        assert!(
            per_year >= FEE_BAND_MIN_CKB && per_year <= FEE_BAND_MAX_CKB,
            "the five-plus fee ({per_year} CKB/year) left the band decision 0009 fixed \
             ({FEE_BAND_MIN_CKB}..{FEE_BAND_MAX_CKB} CKB/year)"
        );
    }

    #[test]
    fn referral_cut_is_a_tenth_and_never_more() {
        let ckb = 100_000_000u64;
        assert_eq!(referral_cut(registration_fee(b"telmo", 1)), 500 * ckb);
        assert_eq!(referral_cut(registration_fee(b"a", 1)), 50_000 * ckb);

        // Exactly a tenth for every price in the schedule, at every term: the fees
        // are whole thousands of CKB, so the division is exact and nothing is lost.
        // Children too: a fifth of a whole thousand is still a whole thousand.
        for label in [&b"a"[..], b"ab", b"abc", b"acme", b"telmo", &[b'a'; 40], b"shop.telmo", b"alice.acme"] {
            for years in [1u64, 3, 10] {
                let fee = registration_fee(label, years);
                let name = core::str::from_utf8(label).unwrap();
                assert_eq!(referral_cut(fee) * 10, fee, "{name}, {years} years");
            }
        }

        // The rounding may only ever favour the treasury, never the inviter.
        for fee in [0u64, 1, 99, 101, 999, u64::MAX] {
            assert!(referral_cut(fee) * 10 <= fee || fee == u64::MAX);
        }
        assert_eq!(referral_cut(0), 0);
        assert_eq!(referral_cut(99), 0); // below a hundred shannons there is nothing to split
    }

    #[test]
    fn a_sale_fee_is_one_percent_and_the_seller_keeps_the_rest() {
        let ckb = 100_000_000u64;
        assert_eq!(sale_fee(10_000 * ckb), 100 * ckb);
        // One percent of this is 10 CKB, too small to be a cell, so the flat cell is
        // charged instead: 63 CKB, which is 6.3% of the sale.
        assert_eq!(sale_fee(1_000 * ckb), 63 * ckb);
        assert_eq!(sale_fee(0), 0);

        // The two halves are the whole price: a buyer is never asked for more than
        // the number they were shown. True in all three bands, which is the point of
        // taking the fee out of the seller's side rather than adding it to the buyer's.
        for price in [1_000 * ckb, 250 * ckb, 7 * ckb, 12_345 * ckb, 1] {
            let fee = sale_fee(price);
            assert!(fee.saturating_add(price - fee) == price, "price {price}");
            assert!(fee <= price, "the fee can never exceed the sale, price {price}");
        }

        // In the band where the rate applies, it rounds down and never up.
        for price in [6_300 * ckb, 12_345 * ckb, 1_000_000 * ckb] {
            assert!(
                sale_fee(price) * 100 <= price * SALE_FEE_PERCENT,
                "the rate must round down, price {price}"
            );
        }

        // The three bands, at every edge of each. There is no fourth band, so these
        // eight assertions are the whole rule.
        assert_eq!(sale_fee(629 * ckb), 0); // a cell would be more than a tenth
        assert_eq!(sale_fee(630 * ckb), 63 * ckb); // exactly a tenth: charged
        assert_eq!(sale_fee(1_000 * ckb), 63 * ckb); // 6.3%
        assert_eq!(sale_fee(6_299 * ckb), 63 * ckb); // still the flat cell
        assert_eq!(sale_fee(6_300 * ckb), 63 * ckb); // and one percent, which is the same figure
        assert_eq!(sale_fee(6_400 * ckb), 64 * ckb); // the rate takes over
        assert_eq!(sale_fee(100 * ckb), 0);
        assert_eq!(sale_fee(1), 0);

        // The rate never exceeds what SALE_FEE_MAX_PERCENT says, anywhere.
        for price in [630 * ckb, 1_000 * ckb, 3_000 * ckb, 6_299 * ckb, 6_300 * ckb, 1_000_000 * ckb] {
            let fee = sale_fee(price);
            assert!(
                fee * 100 <= price * SALE_FEE_MAX_PERCENT,
                "price {price} pays {fee}, which is more than the most we would charge"
            );
        }

        // The band where the fee is waived leaves the seller the whole price, which is
        // what makes the listing floor the seller's own cell rather than a multiple of it.
        for price in [1 * ckb, 63 * ckb, 100 * ckb, 629 * ckb] {
            assert_eq!(price - sale_fee(price), price, "price {price}");
        }

        // The function only ever rises with the price: no price pays more than a dearer
        // one, which is the property a two-step schedule is easiest to get wrong on.
        let mut last = 0u64;
        let mut p = 0u64;
        while p <= 20_000 * ckb {
            let fee = sale_fee(p);
            assert!(fee >= last, "fee fell from {last} to {fee} at price {p}");
            last = fee;
            p += 7 * ckb;
        }
    }

    #[test]
    fn a_term_is_whole_years_rounded_up() {
        assert_eq!(years_for_term(SECONDS_PER_YEAR), 1);
        assert_eq!(years_for_term(SECONDS_PER_YEAR * 10), 10);
        // Any remainder buys another year, so no part of a term is free.
        assert_eq!(years_for_term(SECONDS_PER_YEAR + 1), 2);
        assert_eq!(years_for_term(1), 1);
        // A zero term is zero years: register rejects it on the MIN_TERM_YEARS check
        // rather than here, so this must not silently round up to a paid year.
        assert_eq!(years_for_term(0), 0);
        // Saturating, not panicking, on a term nobody could pay for. The add clamps
        // at u64::MAX, so this is the floor and not the rounded-up value.
        assert_eq!(years_for_term(u64::MAX), u64::MAX / SECONDS_PER_YEAR);
    }

    /// Pinned so the TypeScript codec can be checked against bytes it did not make.
    /// ns = 0x11 x 20, label "alice", owner = 0x22 x 20, secret = 0x33 x 32.
    #[test]
    fn commitment_vector_is_pinned() {
        let c = commitment(&[0x11u8; NAMESPACE_LEN], b"alice", &[0x22u8; OWNER_HASH_LEN], &[0x33u8; SECRET_LEN]);
        let hex: String = c.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(hex, "536ede10fb9f4f9b466819d5315b44abc66fd94c2e009659e7b6dfbf1eab278f", "commitment vector");
    }

    #[test]
    fn commitment_is_deterministic_and_binding() {
        let ns = [0x11u8; NAMESPACE_LEN];
        let label = b"alice";
        let owner = [0x22u8; OWNER_HASH_LEN];
        let secret = [0x33u8; SECRET_LEN];
        let base = commitment(&ns, label, &owner, &secret);
        assert_eq!(base, commitment(&ns, label, &owner, &secret)); // deterministic
                                                                   // every input is bound, changing any one changes the commitment
        assert_ne!(base, commitment(&[0x99u8; NAMESPACE_LEN], label, &owner, &secret)); // namespace
        assert_ne!(base, commitment(&ns, b"bob", &owner, &secret)); //         label
        assert_ne!(
            base,
            commitment(&ns, label, &[0x99u8; OWNER_HASH_LEN], &secret)
        ); // owner
        assert_ne!(base, commitment(&ns, label, &owner, &[0x99u8; SECRET_LEN]));
        //     secret
    }

    #[test]
    fn account_id_derivation() {
        let a = account_id(b"alice");
        assert_eq!(a, account_id(b"alice")); // deterministic
        assert_ne!(a, account_id(b"bob"));
        assert_ne!(a, ROOT_ID);
        assert_eq!(&a[..], &ckb_blake2b256(b"alice")[..ID_LEN]); // prefix of the hash
    }

    #[test]
    fn witness_roundtrip() {
        let w = WitnessData {
            records: vec![
                RecordEntry {
                    key: b"address.60".to_vec(),
                    label: b"main".to_vec(),
                    value: vec![0xde, 0xad, 0xbe, 0xef],
                    ttl: 300,
                },
                RecordEntry {
                    key: b"profile.x".to_vec(),
                    label: vec![],
                    value: b"alice".to_vec(),
                    ttl: 0,
                },
            ],
        };
        let enc = w.encode();
        assert_eq!(WitnessData::decode(&enc).unwrap(), w);
        assert!(WitnessData::decode(&enc[..enc.len() - 1]).is_err()); // truncated
        assert!(WitnessData::decode(b"").is_err()); // empty (missing record count)
    }

    #[test]
    fn witness_default_roundtrips() {
        let w = WitnessData::default();
        assert_eq!(WitnessData::decode(&w.encode()).unwrap(), w);
    }

    #[test]
    fn build_then_parse() {
        let id = account_id(b"alice");
        let owner = [0x42u8; OWNER_HASH_LEN];
        let (data, payload) =
            build_account(&WitnessData::default(), &ROOT_ID, 123, &owner, &owner, b"alice");
        let a = AccountData::parse(&data).unwrap();
        assert_eq!(a.id(), id); // derived from the label
        assert_eq!(a.next(), ROOT_ID);
        assert_eq!(a.expired_at(), 123);
        assert_eq!(a.owner_lock_hash(), &owner);
        assert_eq!(a.account(), b"alice");
        assert_eq!(&ckb_blake2b256(&payload)[..], a.witness_hash());
    }

    #[test]
    fn action_roundtrip() {
        assert_eq!(Action::from_bytes(b"register"), Ok(Action::Register));
        assert_eq!(Action::from_bytes(b"transfer"), Ok(Action::Transfer));
        assert_eq!(Action::from_bytes(b"nope"), Err(Error::UnknownAction));
    }

    #[test]
    fn build_then_parse_round_trips() {
        let owner = [0x42u8; OWNER_HASH_LEN];
        let manager = [0x99u8; OWNER_HASH_LEN];
        let (data, payload) =
            build_account(&WitnessData::default(), &ROOT_ID, 123, &owner, &manager, b"alice");
        assert_eq!(data.len(), DATA_HEADER_LEN + 5);
        assert_eq!(data[OFF_VERSION], VERSION_V3);
        let a = AccountData::parse(&data).unwrap();
        assert_eq!(a.id(), account_id(b"alice"));
        assert_eq!(a.next(), ROOT_ID);
        assert_eq!(a.expired_at(), 123);
        assert_eq!(a.owner_lock_hash(), &owner);
        assert_eq!(a.manager_lock_hash(), &manager);
        assert!(a.is_delegated());
        assert_eq!(a.account(), b"alice");
        assert_eq!(&ckb_blake2b256(&payload)[..], a.witness_hash());
    }

    #[test]
    fn undelegated_means_manager_equals_owner() {
        let owner = [0x42u8; OWNER_HASH_LEN];
        let (data, _) = build_account(&WitnessData::default(), &ROOT_ID, 123, &owner, &owner, b"alice");
        let a = AccountData::parse(&data).unwrap();
        assert!(!a.is_delegated());
        assert_eq!(a.manager_lock_hash(), &owner);
    }

    #[test]
    fn the_root_is_the_empty_label_and_its_id_is_zero() {
        let (data, _) =
            build_account(&WitnessData::default(), &ROOT_ID, 0, &ROOT_OWNER, &ROOT_OWNER, b"");
        let a = AccountData::parse(&data).unwrap();
        assert_eq!(a.id(), ROOT_ID);
        assert_eq!(data.len(), DATA_HEADER_LEN);
        // blake2b of nothing is not zero: the root is special-cased, never hashed, and
        // this is the line that keeps that from being forgotten.
        assert_ne!(&account_id(b"")[..], &ROOT_ID[..]);
    }

    #[test]
    fn expiry_fills_five_bytes_and_refuses_a_sixth() {
        let owner = [0x42u8; OWNER_HASH_LEN];
        let (data, _) =
            build_account(&WitnessData::default(), &ROOT_ID, MAX_EXPIRED_AT, &owner, &owner, b"a");
        assert_eq!(AccountData::parse(&data).unwrap().expired_at(), MAX_EXPIRED_AT);
        // One past the field must fail loudly, not wrap into some year in the past.
        let r = std::panic::catch_unwind(|| {
            build_account_data(&[0u8; 32], &ROOT_ID, MAX_EXPIRED_AT + 1, &owner, &owner, b"a")
        });
        assert!(r.is_err(), "an expiry past five bytes must not be silently truncated");
    }

    /// Property/fuzz test of the uniqueness linked-list (SPEC §3), the single
    /// highest-risk invariant. A deterministic random sequence of `register`
    /// (insert via `between`) and `recycle` (splice via the immediate predecessor)
    /// ops is applied to a model list; after every op we assert the structural
    /// invariants. The decisive one is the **partition property**: any id that is
    /// not already a node is covered by *exactly one* predecessor, which is what
    /// guarantees a name can never be registered twice.
    #[test]
    fn linkedlist_invariant_under_random_ops() {
        use std::collections::BTreeMap;

        // Deterministic PRNG (fixed seed → reproducible). Not cryptographic.
        struct Lcg(u64);
        impl Lcg {
            fn next_u64(&mut self) -> u64 {
                self.0 = self
                    .0
                    .wrapping_mul(6364136223846793005)
                    .wrapping_add(1442695040888963407);
                self.0
            }
            fn id(&mut self) -> Id {
                let mut x = [0u8; ID_LEN];
                for chunk in x.chunks_mut(8) {
                    let v = self.next_u64().to_le_bytes();
                    chunk.copy_from_slice(&v[..chunk.len()]);
                }
                x
            }
        }

        // `next` maps each live id to its successor. Genesis: root -> root.
        let mut next: BTreeMap<Id, Id> = BTreeMap::new();
        next.insert(ROOT_ID, ROOT_ID);

        // Follow `next` from root: must visit every node exactly once and return.
        let check_cycle = |next: &BTreeMap<Id, Id>| {
            let mut seen = 0usize;
            let mut cur = ROOT_ID;
            loop {
                let nx = *next.get(&cur).expect("dangling next pointer");
                seen += 1;
                assert!(
                    seen <= next.len(),
                    "cycle longer than node count (list broken)"
                );
                cur = nx;
                if cur == ROOT_ID {
                    break;
                }
            }
            assert_eq!(seen, next.len(), "cycle does not cover all nodes");
        };

        // The unique predecessor whose open range (p, next[p]) contains `id`.
        let find_pred = |next: &BTreeMap<Id, Id>, id: &Id| -> Option<Id> {
            let mut found = None;
            for (p, nx) in next.iter() {
                if between(p, nx, id) {
                    assert!(
                        found.is_none(),
                        "TWO predecessors cover one id, partition broken"
                    );
                    found = Some(*p);
                }
            }
            found
        };

        let mut rng = Lcg(0x0123_4567_89ab_cdef);
        for step in 0..8_000u32 {
            // Periodically probe the partition with fresh random ids.
            if step % 8 == 0 {
                for _ in 0..4 {
                    let probe = rng.id();
                    if probe == ROOT_ID || next.contains_key(&probe) {
                        continue;
                    }
                    assert!(
                        find_pred(&next, &probe).is_some(),
                        "no predecessor covers a fresh id"
                    );
                }
            }

            if rng.next_u64() % 3 == 0 && next.len() > 1 {
                // recycle a random non-root node
                let victims: Vec<Id> = next.keys().copied().filter(|k| *k != ROOT_ID).collect();
                let victim = victims[(rng.next_u64() as usize) % victims.len()];
                let p = *next
                    .iter()
                    .find(|(_, nx)| **nx == victim)
                    .map(|(p, _)| p)
                    .unwrap();
                // x must be p's immediate successor (mirrors the contract's M-2 check).
                assert_eq!(next[&p], victim);
                let after = next[&victim];
                next.insert(p, after);
                next.remove(&victim);
            } else {
                // register a fresh id
                let id = rng.id();
                if id == ROOT_ID || next.contains_key(&id) {
                    continue;
                }
                let p = find_pred(&next, &id).expect("a fresh id always has a predecessor");
                assert!(between(&p, &next[&p], &id));
                let after = next[&p];
                next.insert(id, after);
                next.insert(p, id);
            }
            check_cycle(&next);

            // ids stay unique by construction (BTreeMap keys); assert no node points
            // at a non-existent successor (every `next` value is a live node).
            for nx in next.values() {
                assert!(next.contains_key(nx), "next points at a recycled node");
            }
        }
        assert!(next.len() > 10, "fuzz should have accumulated live names");
    }
}

#[cfg(test)]
mod price_tests {
    use super::*;
    const CKB: u64 = 100_000_000;

    #[test]
    fn price_data_round_trips_and_rejects_the_rest() {
        for bps in [PRICE_FACTOR_MIN, 5_000, PRICE_FACTOR_MAX] {
            assert_eq!(parse_price_factor(&price_data(bps)), Some(bps));
        }
        assert_eq!(parse_price_factor(&price_data(PRICE_FACTOR_MIN - 1)), None);
        assert_eq!(parse_price_factor(&price_data(PRICE_FACTOR_MAX + 1)), None);
        assert_eq!(parse_price_factor(&price_data(0)), None);
        let mut d = price_data(5_000);
        d[0] = 2; // unknown version
        assert_eq!(parse_price_factor(&d), None);
        assert_eq!(parse_price_factor(&price_data(5_000)[..4]), None); // short
        assert_eq!(parse_price_factor(&[]), None);
    }

    #[test]
    fn the_factor_only_ever_lowers_the_fee() {
        let fee = registration_fee(b"telmo", 1); // 5 000 CKB
        assert_eq!(apply_price_factor(fee, PRICE_FACTOR_MAX), fee);
        assert_eq!(apply_price_factor(fee, 5_000), fee / 2);
        // The floor lands exactly on the smallest treasury output, 63 CKB.
        assert_eq!(apply_price_factor(fee, PRICE_FACTOR_MIN), 63 * CKB);
        // A one-character name at the floor is still a hundred times a long one.
        assert_eq!(apply_price_factor(registration_fee(b"a", 1), PRICE_FACTOR_MIN), 6_300 * CKB);
        // Out of range is clamped, never amplified.
        assert_eq!(apply_price_factor(fee, 20_000), fee);
    }

    #[test]
    fn a_step_is_at_most_a_sixteenth_either_way() {
        assert!(price_step_ok(10_000, 9_375)); // -6.25%
        assert!(!price_step_ok(10_000, 9_374));
        assert!(price_step_ok(8_000, 8_500)); // +6.25%
        assert!(!price_step_ok(8_000, 8_501));
        assert!(price_step_ok(126, 126));
        // The old quarter is now well outside.
        assert!(!price_step_ok(10_000, 7_500));
    }
}
