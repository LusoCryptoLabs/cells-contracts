//! `account-cell-type`, the AccountCell type script (Phase 2, permissionless).
//!
//! Runs once per script group, and, because CKB runs type scripts on inputs as
//! well as outputs, it is the *sole, comprehensive* guardian of every
//! AccountCell. The cell's lock is a uniform always-success (`account-lock`), so
//! all authorization lives here (decision 0002):
//!
//!   * **System actions** (`register`, `renew`, `recycle`) are permissionless,
//!     anyone may drive them. The type script guarantees the predecessor is
//!     preserved byte-for-byte except its `next` pointer (capacity and lock
//!     included), so a stranger splicing in a new name cannot harm an owner.
//!   * **Owner actions** (`edit_records`, `edit_manager`, `transfer`) require the
//!     tx to spend a cell under the account's `owner_lock_hash`, auth delegated
//!     to the owner's own wallet lock.
//!   * **Genesis** must consume the one-time genesis-token (a type script can't see
//!     global state, so that token is what makes a forged second root impossible,
//!     SECURITY.md H-1).
#![no_std]
#![no_main]

use alloc::vec::Vec;

use ckb_std::ckb_constants::Source;
use ckb_std::ckb_types::prelude::{Entity, Unpack};
use ckb_std::error::SysError;
use ckb_std::high_level::{
    load_cell_capacity, load_cell_data, load_cell_lock, load_cell_lock_hash, load_cell_type_hash, load_header,
    load_input, load_script, load_script_hash, load_witness_args, QueryIter,
};

use cells_core::{
    apply_price_factor, between, ckb_blake2b256, commitment, covers, parent_label, price_floor,
    NAMESPACE_LEN,
    parse_price_factor, referral_cut, registration_fee, sale_fee, validate_label, years_for_term, AccountData, Action, Error,
    COMMIT_MIN_DELAY,
    DATA_HEADER_LEN, PRICE_CELL_TYPE_HASH, PRICE_FACTOR_MAX, MAX_TERM_YEARS, MIN_TERM_YEARS, OWNER_HASH_LEN, ROOT_ID, ROOT_OWNER, SECONDS_PER_YEAR,
    SALE_ARGS_LEN, SALE_LOCK_CODE_HASH, SECRET_LEN, TREASURY_LOCK_HASH,
};

ckb_std::entry!(program_entry);
ckb_std::default_alloc!();

/// Grace period (seconds) after expiry before a name may be recycled: **thirty days**,
/// the convention a domain owner already expects.
///
/// It was zero, which meant a forgotten renewal could be taken the same second it
/// lapsed, by anybody, since recycling is permissionless. Nobody lost a name that way,
/// because the earliest registrations still run to 2028, but the first one to lapse
/// would have found out the hard way. The old TODO here said to read the value from the
/// ConfigCell, which no longer exists (SECURITY.md H-1 removed it), so there is nowhere
/// to read it from: it is a constant compiled in, and changing it is a contract upgrade.
///
/// During the grace period the name keeps working exactly as before: the cell is still
/// live, so it still resolves and can still be renewed by anyone. What the period buys
/// is only that nobody else may take it.
const GRACE_SECONDS: u64 = 30 * 86_400;

pub fn program_entry() -> i8 {
    match main() {
        Ok(()) => 0,
        Err(e) => e as i8,
    }
}

/// An AccountCell guarded by this type script, with its absolute index.
struct Cell {
    index: usize,
    data: Vec<u8>,
}

fn main() -> Result<(), Error> {
    let self_hash = load_script_hash().map_err(|_| Error::Encoding)?;
    let inputs = collect(Source::Input, &self_hash)?;
    let outputs = collect(Source::Output, &self_hash)?;

    // (1) Integrity, every output AccountCell: valid label, correct id and
    // witness_hash. Input AccountCells are trusted by induction (validated when
    // created). The root sentinel (empty label) is exempt from label/id checks.
    for c in &outputs {
        let a = AccountData::parse(&c.data)?;
        // The id is derived from the label (decision 0015), so there is no stored id
        // to check against it; what binds a name to its id is now the hash itself.
        // The root sentinel is the empty label and is exempt from the charset rule.
        if !a.account().is_empty() {
            validate_label(a.account())?;
        }
        let payload = load_witness_payload(c.index)?;
        if ckb_blake2b256(&payload)[..] != *a.witness_hash() {
            return Err(Error::WitnessHashMismatch);
        }
    }

    // Genesis: no existing AccountCells are spent, bootstrap the root (SPEC §3.3).
    // Token-gated; only the root sentinel may be created this way.
    if inputs.is_empty() {
        return validate_genesis(&outputs);
    }

    // (1b) Every output AccountCell must wear the SAME lock as the input AccountCells.
    // That lock is the always-success `account-lock` (the whole design, decision 0002)
    // and the invariant every action preserves, established at genesis. Without this,
    // `register` accepted a new cell under any lock, with three consequences:
    //   * an unspendable lock freezes the cell's id-range forever, because it can never
    //     be spent as a predecessor again (a permanent uniqueness/availability DoS);
    //   * a lock equal to the treasury lets the new cell's own refundable rent be
    //     counted as the registration fee (require_treasury sums outputs by lock);
    //   * a lock equal to an inviter lets the same rent be counted as the referral cut.
    // Pinning it to the inputs' lock also makes reject_cell_lock_authority fire on an
    // owner set to the account-lock, which it could otherwise miss. Genesis is exempt:
    // it has no AccountCell input, is token-gated, and runs exactly once.
    let account_lock = lock_hash(&inputs[0], Source::Input)?;
    for c in &outputs {
        if lock_hash(c, Source::Output)? != account_lock {
            return Err(Error::CellLockNotAccountLock);
        }
    }

    // (2) Dispatch on the declared action.
    match load_action()? {
        Action::Register => validate_register(&inputs, &outputs),
        // Owner/manager split (decision 0006): record edits are owner-OR-manager;
        // setting the manager (delegation) is owner-only and may migrate v1 → v2.
        Action::EditRecords => validate_edit(&inputs, &outputs),
        Action::EditManager => validate_set_manager(&inputs, &outputs),
        Action::Transfer => validate_transfer(&inputs, &outputs),
        Action::Renew => validate_renew(&inputs, &outputs),
        Action::Recycle => validate_recycle(&inputs, &outputs),
    }
}

// --- loading ---------------------------------------------------------------

/// Collect every AccountCell (our type hash) in `source`, with absolute indices.
fn collect(source: Source, self_hash: &[u8; 32]) -> Result<Vec<Cell>, Error> {
    let mut out = Vec::new();
    let mut i = 0;
    loop {
        match load_cell_type_hash(i, source) {
            Ok(opt) => {
                if opt.as_ref() == Some(self_hash) {
                    let data =
                        load_cell_data(i, source).map_err(|_| Error::MalformedAccountData)?;
                    out.push(Cell { index: i, data });
                }
                i += 1;
            }
            Err(SysError::IndexOutOfBound) => return Ok(out),
            Err(_) => return Err(Error::Encoding),
        }
    }
}

/// The AccountCell witness payload for cell index `i` lives in `witnesses[i]`
/// (`output_type` field), read reliably via `Source::Input` indexing.
fn load_witness_payload(i: usize) -> Result<Vec<u8>, Error> {
    let wa = load_witness_args(i, Source::Input).map_err(|_| Error::WitnessHashMismatch)?;
    let raw = wa
        .output_type()
        .to_opt()
        .ok_or(Error::WitnessHashMismatch)?
        .raw_data();
    Ok(raw.to_vec())
}

/// Read the protocol action from `witnesses[0].input_type` (Phase 1; SPEC §6).
fn load_action() -> Result<Action, Error> {
    let witness = load_witness_args(0, Source::Input).map_err(|_| Error::UnknownAction)?;
    let raw = witness
        .input_type()
        .to_opt()
        .ok_or(Error::UnknownAction)?
        .raw_data();
    Action::from_bytes(raw.as_ref())
}

/// The cell's capacity must not shrink across the action.
///
/// `predecessor_preserved` has always done this for `register`, and nothing else did.
/// `recycle`, `renew`, `edit_records`, `edit_manager` and `transfer` each pinned every
/// byte of data and the lock and left the capacity free. Every AccountCell wears an
/// always-success lock, and three of those actions are permissionless, so a stranger
/// could set the surviving output's capacity to the occupied minimum and take the
/// difference: the owner's refundable rent. The name survives, the deposit does not.
fn capacity_not_reduced(input: &Cell, output: &Cell) -> Result<(), Error> {
    let cap_in = load_cell_capacity(input.index, Source::Input).map_err(|_| Error::Encoding)?;
    let cap_out = load_cell_capacity(output.index, Source::Output).map_err(|_| Error::Encoding)?;
    if cap_out < cap_in {
        return Err(Error::StructuralDrift);
    }
    Ok(())
}

fn lock_hash(cell: &Cell, source: Source) -> Result<[u8; 32], Error> {
    load_cell_lock_hash(cell.index, source).map_err(|_| Error::Encoding)
}

// --- per-action validators (SPEC §7) ---------------------------------------

/// Genesis: create the root account (id == next == 0) from nothing.
///
/// **Singleton (trustless):** the tx must consume the one-time **genesis-token**,
/// an input whose type-script hash equals this script's args (the namespace id).
/// The token is a type-id cell: globally unique and unrecreatable, so after genesis
/// it is gone and no second root can ever be created, and it cannot be forged (its
/// type hash is bound to a now-spent outpoint). This is the genesis authorization
/// *and* the singleton, there is no separate ConfigCell to forge (SECURITY.md H-1).
fn validate_genesis(outputs: &[Cell]) -> Result<(), Error> {
    require_genesis_token(&namespace_id()?)?;
    if outputs.len() != 1 {
        return Err(Error::LinkedListBroken);
    }
    let root = AccountData::parse(&outputs[0].data)?;
    if root.id() != ROOT_ID || root.next() != ROOT_ID {
        return Err(Error::LinkedListBroken);
    }
    // The root is a sentinel, not a name, and the v1/v2 discriminator argument rests
    // on it being exactly the header length with an empty label. Genesis checked
    // neither, so a seeded root could have carried a label or a manager field.
    if outputs[0].data.len() != DATA_HEADER_LEN || !root.account().is_empty() {
        return Err(Error::MalformedAccountData);
    }
    // The sentinel is protocol-owned: no owner, no manager. With one it becomes a
    // name somebody can edit, transfer and name as a referral inviter. The live
    // Pudge root is all-zero (read on 2026-09-11); this pins it for the next deploy.
    if root.owner_lock_hash() != ROOT_OWNER || root.manager_lock_hash() != ROOT_OWNER {
        return Err(Error::MalformedAccountData);
    }
    Ok(())
}

/// Register: input `[p]`; outputs `[p', x]` (predecessor-then-new). Permissionless.
///
/// Safety without a signature: the predecessor `p` is preserved byte-for-byte
/// except its `next` pointer, witness_hash, expiry, owner, account, cell lock and
/// capacity all fixed, so whoever drives the tx cannot harm `p`'s owner. The only
/// possible effect is splicing a well-formed new name `x` into `p`'s range. The
/// new cell's id↔label and witness_hash integrity were already checked in `main`.
fn validate_register(inputs: &[Cell], outputs: &[Cell]) -> Result<(), Error> {
    if inputs.len() != 1 || outputs.len() != 2 {
        return Err(Error::LinkedListBroken);
    }
    let p = AccountData::parse(&inputs[0].data)?;
    let p_new = AccountData::parse(&outputs[0].data)?;
    let x = AccountData::parse(&outputs[1].data)?;

    // Nobody registers the sentinel's id. Unreachable while the root is live, since
    // `between` excludes both endpoints and the only wraparound node ends at zero,
    // but this is the second half of the pair with the recycle guard: either check
    // alone closes the hole, and a rule this cheap should not depend on the other.
    if x.id() == ROOT_ID {
        return Err(Error::RootNotRecyclable);
    }

    // A real name must have a usable owner (SECURITY.md L-1): an all-zero
    // `owner_lock_hash` would make the name permanently un-editable/un-transferable.
    reject_null_owner(x.owner_lock_hash())?;
    // ...and not the always-success lock every AccountCell wears, which anyone can
    // satisfy. The manager is checked too.
    let x_lock = lock_hash(&outputs[1], Source::Output)?;
    reject_cell_lock_authority(x.owner_lock_hash(), &x_lock)?;
    reject_cell_lock_authority(x.manager_lock_hash(), &x_lock)?;
    // A name is registered UNDELEGATED: manager == owner. `transfer` already forces
    // this, so a delegation cannot survive a change of hands, and the commitment does
    // not cover the manager, so whoever lands the registration would otherwise choose
    // it. Delegating is `edit_manager`, which the owner has to sign.
    if x.manager_lock_hash() != x.owner_lock_hash() {
        return Err(Error::StructuralDrift);
    }

    // The new id must sit strictly inside the predecessor's old range (SPEC §3.1).
    if !between(&p.id(), &p.next(), &x.id()) {
        return Err(Error::NotInPredecessorRange);
    }
    // Relink: p'.id == p.id, p'.next == x.id, x.next == p.next_old.
    if p_new.id() != p.id() || p_new.next() != x.id() || x.next() != p.next() {
        return Err(Error::LinkedListBroken);
    }
    // Predecessor fully preserved except `next` (this is what makes it safe for
    // an unauthenticated party to spend someone else's predecessor cell).
    predecessor_preserved(&inputs[0], &p, &outputs[0], &p_new)?;

    // Pricing: the new name must lock at least `price_floor(len)` CKB (refundable
    // rent; short names cost more, anti-squatting).
    let need = price_floor(x.account().len());
    let paid = load_cell_capacity(outputs[1].index, Source::Output).map_err(|_| Error::Encoding)?;
    if paid < need {
        return Err(Error::InsufficientPrice);
    }

    // Sub-names (decision 0008): a dotted label may only be created by the owner of
    // its parent. Without this, relaxing the charset to allow dots would let anyone
    // squat `shop.telmo`. The parent is supplied as a **cell dep** (a dep must be a
    // live cell, so this proves the parent exists) and is left untouched.
    if let Some(parent) = parent_label(x.account()) {
        let pdata = require_parent(parent)?;
        let p = AccountData::parse(&pdata)?;
        require_owner(p.owner_lock_hash())?;
        // A sub-name must not outlive the parent that authorized it, or the parent
        // could lapse and be recycled while its children kept resolving.
        if x.expired_at() > p.expired_at() {
            return Err(Error::ParentOutlived);
        }
    }

    // Commit-reveal (anti front-running, decision 0004): the tx must also spend a
    // CommitCell whose data == blake2b(namespace ‖ label ‖ owner ‖ secret), with the
    // secret revealed in the new cell's witness, and that input must be old enough
    // (its `since` a relative-timestamp >= MIN_DELAY). The commitment hid the label,
    // so a front-runner cannot have a matured commit for it.
    let commit_index = require_commit(&x, outputs[1].index)?;

    // The term, and what it costs (decision 0009). "Now" is the CommitCell's block
    // timestamp (recent, since the commit was just matured), read via a header_dep on
    // that block. The client can read that same header before it builds, so the term
    // below is exact at build time, not a guess a late block can invalidate.
    //
    // This also subsumes the old L-2 future-expiry check: a term of at least a year
    // is, in particular, a term that has not already ended.
    let now = header_time_seconds(commit_index)?;
    let term = x.expired_at().saturating_sub(now);
    if term < MIN_TERM_YEARS.saturating_mul(SECONDS_PER_YEAR) {
        return Err(Error::ExpiryTooSoon);
    }
    let years = years_for_term(term);
    if years > MAX_TERM_YEARS {
        return Err(Error::TermTooLong);
    }
    // A referral (decision 0011) redirects a tenth of the fee to whoever brought the
    // buyer in. It is deducted from the treasury's share, never added to the price,
    // so the buyer pays the same either way.
    // The schedule is a ceiling; the price cell, if presented, may discount it
    // (decision 0014). The referral's tenth is then a tenth of what is charged.
    let fee = apply_price_factor(registration_fee(x.account(), years), price_factor()?);
    let discount = referral_discount(referral_cut(fee))?;
    require_treasury(fee.saturating_sub(discount))?;
    Ok(())
}

/// What an inviter has earned on this registration, or zero if none qualifies.
///
/// The inviter is an existing `.cell` name, presented as a **cell dep** exactly as a
/// parent is (a dep must be live, so this proves the name exists without disturbing
/// it), and paid through the only owner identity a cell carries: its
/// `owner_lock_hash`. Paying it `cut` buys `cut` off what the treasury is owed.
///
/// Two things disqualify an inviter, and both exist because the contract cannot tell
/// a stranger's wallet from a second wallet of your own:
///   * the treasury, or a single output would count as both the fee and the cut;
///   * anyone who signed this transaction, so your own change can never be read as
///     a referral payment.
///
/// Inviting yourself is covered by the second: `require_commit` has already forced
/// the CommitCell to be held by the new name's owner, so the owner always has an
/// input here. An explicit owner check would be unreachable, and an unreachable
/// guard is one that can be wrong without any test noticing.
///
/// None of that makes self-dealing impossible. Two wallets and a name defeat it, and
/// decision 0011 says so rather than pretending otherwise: the effect is that the
/// fee schedule is a tenth lower for anyone determined, and the rules decide whether
/// that tenth reaches a promoter or the sharpest buyer. What they do guarantee is
/// that it cannot happen by accident, or by a client quietly paying it to itself.
///
/// Permissive by design: an unqualified or unpaid inviter is not an error, it simply
/// earns nothing and the full fee falls due.
fn referral_discount(cut: u64) -> Result<u64, Error> {
    if cut == 0 {
        return Ok(0);
    }
    let self_hash = load_script_hash().map_err(|_| Error::Encoding)?;
    let mut i = 0usize;
    loop {
        match load_cell_type_hash(i, Source::CellDep) {
            Ok(opt) => {
                if opt.as_ref() == Some(&self_hash) {
                    let data = load_cell_data(i, Source::CellDep)
                        .map_err(|_| Error::MalformedAccountData)?;
                    let inviter = AccountData::parse(&data)?;
                    let owner = inviter.owner_lock_hash();
                    // A twenty-byte owner against a thirty-two-byte constant never
                    // matched, so this guard used to fail OPEN under truncation and the
                    // treasury could name itself as inviter. Compare the prefix.
                    // F-9's third shape: an inviter who is also selling a name here would
                    // otherwise be paid once and credited twice, since both checks count
                    // the same output. What the sales owe them is theirs already.
                    let (_, sales_owe_them) = owed_by_sales(Some(owner))?;
                    if owner != &TREASURY_LOCK_HASH[..OWNER_HASH_LEN]
                        && !signed_by(owner)
                        && paid_to(owner)? >= cut.saturating_add(sales_owe_them)
                    {
                        return Ok(cut);
                    }
                }
                i += 1;
            }
            Err(SysError::IndexOutOfBound) => return Ok(0),
            Err(_) => return Err(Error::Encoding),
        }
    }
}

/// Does any input in this transaction sit under `lock_hash`? Spending a cell is the
/// only way to prove control of a lock, which is why `require_owner` asks the same
/// question; here the answer disqualifies rather than authorizes.
fn signed_by(lock_hash: &[u8]) -> bool {
    QueryIter::new(load_cell_lock_hash, Source::Input).any(|h| h[..OWNER_HASH_LEN] == *lock_hash)
}

/// Does output `i` count as a payment? Only a PURE cell does, one with no type
/// script. Same rule `sale-lock` already applies to a buyer's payment: a type the
/// payee does not control (an always-fail, a joint-custody type) meets the capacity
/// while the funds are not theirs to spend, a burn or a ransom lever on what the
/// protocol earns. A real payment is an ordinary cell.
fn is_pure_output(i: usize) -> Result<bool, Error> {
    Ok(load_cell_type_hash(i, Source::Output).map_err(|_| Error::Encoding)?.is_none())
}

/// What the PURE outputs pay to `lock_hash`, summed like the treasury's own total.
fn paid_to(lock_hash: &[u8]) -> Result<u64, Error> {
    let mut paid: u64 = 0;
    let mut i = 0usize;
    loop {
        match load_cell_lock_hash(i, Source::Output) {
            Ok(h) => {
                if h[..OWNER_HASH_LEN] == *lock_hash && is_pure_output(i)? {
                    let c = load_cell_capacity(i, Source::Output).map_err(|_| Error::Encoding)?;
                    paid = paid.saturating_add(c);
                }
                i += 1;
            }
            Err(SysError::IndexOutOfBound) => return Ok(paid),
            Err(_) => return Err(Error::Encoding),
        }
    }
}

/// The registration fee must land on the treasury lock (decision 0009). Any number of
/// outputs may carry it, so this sums rather than checking one index: a client is free
/// to split, and pinning an index would only make honest transactions harder to build.
///
/// Note that the treasury's own change counts towards the total, so the treasury key
/// registers names for nothing. That is not a hole: paying oneself is a no-op, and the
/// alternative (excluding those outputs) would make the treasury unable to register at
/// all without a second wallet.
/// What the sale locks being spent in this transaction already owe, so a payment cannot
/// answer both them and us.
///
/// **This is the F-9 fix** ([SECURITY.md](../../../docs/SECURITY.md)). `require_treasury`
/// sums the outputs paying the treasury and compares the total with what *this* action
/// needs; `sale-lock` does the same for its own fee; neither knows the other is running,
/// so one output satisfied both and the smaller fee was never paid. Reproduced on
/// 2026-09-14: a renewal batched with a sale paid 5,000 CKB where 5,100 was owed.
///
/// One side is enough, because the strictest requirement binds, and this is the side that
/// can do the arithmetic: a sale's fee is `sale_fee(price)` and the price is in the lock's
/// own args. The reverse (the sale lock computing a registration fee) would need the
/// action, the term and the schedule.
///
/// Returns `(owed_to_treasury, owed_to_lock)`, the second only when `to_lock` is given:
/// the referral cut has the same shape, since an inviter who is also a seller in the same
/// transaction would otherwise be paid once for two obligations.
///
/// **The cancellation exemption is mirrored, not guessed.** `sale-lock` demands nothing for
/// an offer whose seller has an input here, because that seller is cancelling or relisting
/// rather than selling (P7-2). Adding a fee for those would refuse an honest batch, so the
/// same predicate is applied. It is duplicated logic and that is a real cost; the test
/// `a_cancellation_beside_a_registration_owes_no_sale_fee` is what keeps the two in step.
fn owed_by_sales(to_lock: Option<&[u8]>) -> Result<(u64, u64), Error> {
    // An all-zero code hash is a namespace deployed without a sale lock: no real lock can
    // hash to it, so the scan would find nothing. Skipping it saves the walk entirely.
    if SALE_LOCK_CODE_HASH == [0u8; 32] {
        return Ok((0, 0));
    }
    let mut to_treasury: u64 = 0;
    let mut to_them: u64 = 0;
    let mut i = 0usize;
    loop {
        match load_cell_lock(i, Source::Input) {
            Ok(lock) => {
                let args = lock.args().raw_data();
                if lock.code_hash().as_slice() == SALE_LOCK_CODE_HASH && args.len() == SALE_ARGS_LEN {
                    let seller: [u8; 32] = args[..32].try_into().map_err(|_| Error::Encoding)?;
                    // The seller is here, so this offer is being cancelled and owes nothing.
                    if !any_input_under(&seller)? {
                        let price = u64::from_le_bytes(args[32..40].try_into().map_err(|_| Error::Encoding)?);
                        let f = sale_fee(price);
                        to_treasury = to_treasury.saturating_add(f);
                        if let Some(t) = to_lock {
                            if seller[..OWNER_HASH_LEN] == *t {
                                let deposit =
                                    load_cell_capacity(i, Source::Input).map_err(|_| Error::Encoding)?;
                                to_them = to_them
                                    .saturating_add(price.saturating_sub(f))
                                    .saturating_add(deposit);
                            }
                        }
                    }
                }
                i += 1;
            }
            Err(SysError::IndexOutOfBound) => return Ok((to_treasury, to_them)),
            Err(_) => return Err(Error::Encoding),
        }
    }
}

/// Is any input in this transaction locked by `hash`? The sale lock's own test for a
/// seller who is present, repeated here for the same reason and with the same meaning.
fn any_input_under(hash: &[u8; 32]) -> Result<bool, Error> {
    let mut i = 0usize;
    loop {
        match load_cell_lock_hash(i, Source::Input) {
            Ok(h) => {
                if &h == hash {
                    return Ok(true);
                }
                i += 1;
            }
            Err(SysError::IndexOutOfBound) => return Ok(false),
            Err(_) => return Err(Error::Encoding),
        }
    }
}

fn require_treasury(need: u64) -> Result<(), Error> {
    let mut paid: u64 = 0;
    let mut i = 0usize;
    loop {
        match load_cell_lock_hash(i, Source::Output) {
            Ok(h) => {
                if h == TREASURY_LOCK_HASH && is_pure_output(i)? {
                    let c = load_cell_capacity(i, Source::Output).map_err(|_| Error::Encoding)?;
                    paid = paid.saturating_add(c);
                }
                i += 1;
            }
            Err(SysError::IndexOutOfBound) => break,
            Err(_) => return Err(Error::Encoding),
        }
    }
    // F-9: whatever the sale locks in this transaction owe the treasury is theirs, not
    // ours. Demanding only `need` let one output answer both, and the smaller fee was
    // never paid by anybody.
    let (sales_owe, _) = owed_by_sales(None)?;
    if paid < need.saturating_add(sales_owe) {
        return Err(Error::TreasuryUnpaid);
    }
    Ok(())
}

/// The discount factor in basis points, read from the price cell presented as a cell
/// dep (decision 0014), or `PRICE_FACTOR_MAX` (the full price) when there is none.
///
/// The cell is identified by its type-script hash, compiled in like the treasury: a
/// type-id instance, so a look-alike cannot be minted (the hole that removed the old
/// ConfigCell, SECURITY.md H-1). All-zero means no price cell was ever configured.
///
/// **A missing dep, malformed data or an out-of-band factor all fall back to the full
/// price**, so a mistake there can only cost the payer, never the treasury, and a
/// consumed or corrupted cell cannot stop anyone registering. The one failure that does
/// not fall back is a syscall error reading the dep's data, which returns `Encoding` and
/// fails the transaction: unreadable is not the same as absent, and guessing the payer's
/// price from a broken read would be worse than refusing.
fn price_factor() -> Result<u32, Error> {
    if PRICE_CELL_TYPE_HASH == [0u8; 32] {
        return Ok(PRICE_FACTOR_MAX);
    }
    let mut i = 0usize;
    loop {
        match load_cell_type_hash(i, Source::CellDep) {
            Ok(Some(h)) if h == PRICE_CELL_TYPE_HASH => {
                let data = load_cell_data(i, Source::CellDep).map_err(|_| Error::Encoding)?;
                return Ok(parse_price_factor(&data).unwrap_or(PRICE_FACTOR_MAX));
            }
            Ok(_) => i += 1,
            Err(SysError::IndexOutOfBound) => return Ok(PRICE_FACTOR_MAX),
            Err(_) => return Err(Error::Encoding),
        }
    }
}

/// The register tx must spend a CommitCell that matches the revealed name. The
/// secret is read from the new cell's witness (`witnesses[x_index].input_type`);
/// the commitment is recomputed and matched against some input cell's whole data,
/// and that input must carry a relative-timestamp `since >= COMMIT_MIN_DELAY`.
/// Returns the matching CommitCell input index (for the L-2 timestamp read).
fn require_commit(x: &AccountData, x_index: usize) -> Result<usize, Error> {
    let secret = load_register_secret(x_index)?;
    let ns = namespace_id()?;
    let mut owner = [0u8; OWNER_HASH_LEN];
    owner.copy_from_slice(x.owner_lock_hash());
    let want = commitment(&ns, x.account(), &owner, &secret);

    let mut i = 0;
    loop {
        match load_cell_data(i, Source::Input) {
            // A CommitCell is exactly the 32-byte commitment (AccountCell inputs are
            // longer, pure fee cells are empty), so an exact match is unambiguous.
            //
            // It must ALSO be held by the owner it commits to. The commitment is the
            // cell's whole data, so it is public the moment the commit confirms, a
            // full MIN_DELAY before the reveal. Without this check anyone could copy
            // those 32 bytes into a cell of their own, mature it on the same clock,
            // read the secret out of the victim's broadcast reveal and land the
            // registration first. The name still went to the committed owner, but the
            // front-runner chose everything else about it. Binding the holder makes a
            // copied commitment worthless: they cannot produce a cell under the
            // victim's lock. Honest clients already pay the CommitCell to themselves,
            // so this costs them nothing.
            Ok(data) if data.as_slice() == want => {
                let holder = load_cell_lock_hash(i, Source::Input).map_err(|_| Error::Encoding)?;
                if holder[..OWNER_HASH_LEN] != *x.owner_lock_hash() {
                    return Err(Error::CommitNotOwned);
                }
                check_commit_since(i)?;
                return Ok(i);
            }
            Ok(_) => i += 1,
            Err(SysError::IndexOutOfBound) => return Err(Error::CommitMissing),
            Err(_) => return Err(Error::Encoding),
        }
    }
}

/// The block timestamp (seconds) of the block that committed input `index`, read via
/// a header_dep on that block. The CommitCell's age is bounded **below** by
/// `COMMIT_MIN_DELAY`, not above, so this "now" can be older than the real one by as
/// much as the registrant chose to wait. That only ever works against them: a staler
/// clock makes the term longer, so the fee higher, and can register a name that has
/// already lapsed. It can never shorten a term or underpay the treasury.
fn header_time_seconds(index: usize) -> Result<u64, Error> {
    let header = load_header(index, Source::Input).map_err(|_| Error::Encoding)?;
    let ts_ms: u64 = header.raw().timestamp().unpack();
    Ok(ts_ms / 1000)
}

/// The reveal secret, carried in the new cell's `witnesses[x_index].input_type`
/// (its `output_type` already holds the records payload).
fn load_register_secret(x_index: usize) -> Result<[u8; SECRET_LEN], Error> {
    let wa = load_witness_args(x_index, Source::Input).map_err(|_| Error::CommitMissing)?;
    let raw = wa
        .input_type()
        .to_opt()
        .ok_or(Error::CommitMissing)?
        .raw_data();
    if raw.len() != SECRET_LEN {
        return Err(Error::CommitMissing);
    }
    let mut s = [0u8; SECRET_LEN];
    s.copy_from_slice(&raw);
    Ok(s)
}

/// The CommitCell input's `since` must be a **relative-timestamp** (top byte 0xC0:
/// relative=1, metric=timestamp) of at least `COMMIT_MIN_DELAY` seconds, CKB
/// consensus only admits the reveal once the commit is genuinely that old.
fn check_commit_since(index: usize) -> Result<(), Error> {
    let input = load_input(index, Source::Input).map_err(|_| Error::Encoding)?;
    let since: u64 = input.since().unpack();
    const REL_TIMESTAMP_FLAG: u64 = 0xC0; // relative=1 (0x80) | metric=timestamp (0x40)
    if (since >> 56) != REL_TIMESTAMP_FLAG {
        return Err(Error::CommitTooYoung);
    }
    let delay = since & 0x00FF_FFFF_FFFF_FFFF;
    if delay < COMMIT_MIN_DELAY {
        return Err(Error::CommitTooYoung);
    }
    Ok(())
}

/// EditRecords: id/next/account/expired_at, owner, **manager**, layout version and
/// the cell lock all unchanged. The witness may change (records edited). Authorized
/// by co-spending a cell under **either** `owner_lock_hash` **or** `manager_lock_hash`
/// (the delegated manager may edit records but nothing else, decision 0006).
fn validate_edit(inputs: &[Cell], outputs: &[Cell]) -> Result<(), Error> {
    let (ci, co) = one_in_one_out(inputs, outputs)?;
    let i = AccountData::parse(&ci.data)?;
    let o = AccountData::parse(&co.data)?;
    core_fields_unchanged(&i, &o)?;
    if i.expired_at() != o.expired_at() {
        return Err(Error::StructuralDrift);
    }
    if i.owner_lock_hash() != o.owner_lock_hash() || i.manager_lock_hash() != o.manager_lock_hash()
    {
        return Err(Error::StructuralDrift);
    }
    if lock_hash(ci, Source::Input)? != lock_hash(co, Source::Output)? {
        return Err(Error::StructuralDrift);
    }
    capacity_not_reduced(ci, co)?;
    require_owner_or_manager(i.owner_lock_hash(), i.manager_lock_hash())
}

/// EditManager (delegation): set/replace the `manager_lock_hash`. Everything else,
/// id/next/account/expired_at, **owner**, witness/records and the cell lock, is
/// fixed; only the manager changes. The output is a **v2** cell (so a v1 cell is
/// migrated in place on first delegation). **Owner-only** (the manager cannot
/// re-delegate). decision 0006.
fn validate_set_manager(inputs: &[Cell], outputs: &[Cell]) -> Result<(), Error> {
    let (ci, co) = one_in_one_out(inputs, outputs)?;
    let i = AccountData::parse(&ci.data)?;
    let o = AccountData::parse(&co.data)?;
    core_fields_unchanged(&i, &o)?;
    if i.expired_at() != o.expired_at() {
        return Err(Error::StructuralDrift);
    }
    if i.owner_lock_hash() != o.owner_lock_hash() {
        return Err(Error::StructuralDrift);
    }
    if i.witness_hash() != o.witness_hash() {
        return Err(Error::StructuralDrift); // records unchanged, this is not an edit
    }
    if lock_hash(ci, Source::Input)? != lock_hash(co, Source::Output)? {
        return Err(Error::StructuralDrift);
    }
    // An all-zero manager is unreachable by anyone, the owner included, so
    // `edit_records` could never again be co-signed by a delegate: L-1 for the
    // manager field, the same self-harm register/transfer already refuse for owner.
    reject_null_owner(o.manager_lock_hash())?;
    // A delegate anyone can be is not a delegate. Nothing constrained this value
    // before, so a manager could be set to the cell's own always-success lock and
    // every passer-by would have become an editor.
    reject_cell_lock_authority(o.manager_lock_hash(), &lock_hash(co, Source::Output)?)?;
    capacity_not_reduced(ci, co)?;
    require_owner(i.owner_lock_hash())
}

/// Transfer: the only action that may change `owner_lock_hash` (hand the name to a
/// new owner). id/next/account/expired_at and the cell lock unchanged; witness may
/// change. The **manager is reset to the new owner** (so a prior delegate loses edit
/// rights on a sale). The *current* owner authorizes by co-spending a cell under
/// their lock.
fn validate_transfer(inputs: &[Cell], outputs: &[Cell]) -> Result<(), Error> {
    let (ci, co) = one_in_one_out(inputs, outputs)?;
    let i = AccountData::parse(&ci.data)?;
    let o = AccountData::parse(&co.data)?;
    core_fields_unchanged(&i, &o)?;
    if i.expired_at() != o.expired_at() {
        return Err(Error::StructuralDrift);
    }
    if lock_hash(ci, Source::Input)? != lock_hash(co, Source::Output)? {
        return Err(Error::StructuralDrift);
    }
    // What the name publishes travels with it. A transfer hands over the name, it does
    // not rewrite it: changing the records is `edit_records`, which the new owner can do
    // afterwards for themselves.
    //
    // This is what makes a published picture, or a payout address, part of the thing
    // being handed over rather than a courtesy of whoever assembles the transaction. Our
    // own SDK always carried the records across, but nothing made it. A marketplace, an
    // escrow or an aggregator building the transfer could drop them, and someone buying
    // the name that had the picture would receive a name that did not.
    //
    // It costs the sender nothing to satisfy: `main` already requires every output's
    // witness to hash to its own commitment, so pinning the commitment here means the
    // records must actually be present in the transaction, not merely referenced by a
    // hash pointing back into history.
    if i.witness_hash() != o.witness_hash() {
        return Err(Error::StructuralDrift); // records travel with the name
    }
    // The new owner must be usable (SECURITY.md L-1): not all-zero, and not the
    // cell's own always-success lock, which would hand the name to everybody.
    reject_null_owner(o.owner_lock_hash())?;
    reject_cell_lock_authority(o.owner_lock_hash(), &lock_hash(co, Source::Output)?)?;
    capacity_not_reduced(ci, co)?;
    // Manager is reset to the new owner, no lingering delegation across a transfer.
    if o.manager_lock_hash() != o.owner_lock_hash() {
        return Err(Error::StructuralDrift);
    }
    require_owner(i.owner_lock_hash())
}

/// Renew: only `expired_at` grows; everything else (owner, cell lock, witness)
/// fixed. Permissionless, anyone may pay to extend a name (cf. ENS).
fn validate_renew(inputs: &[Cell], outputs: &[Cell]) -> Result<(), Error> {
    let (ci, co) = one_in_one_out(inputs, outputs)?;
    let i = AccountData::parse(&ci.data)?;
    let o = AccountData::parse(&co.data)?;
    core_fields_unchanged(&i, &o)?;
    if i.owner_lock_hash() != o.owner_lock_hash() || i.manager_lock_hash() != o.manager_lock_hash()
    {
        return Err(Error::StructuralDrift);
    }
    if lock_hash(ci, Source::Input)? != lock_hash(co, Source::Output)? {
        return Err(Error::StructuralDrift);
    }
    if o.expired_at() <= i.expired_at() {
        return Err(Error::StructuralDrift);
    }
    if i.witness_hash() != o.witness_hash() {
        return Err(Error::StructuralDrift);
    }
    capacity_not_reduced(ci, co)?;

    // Renewal is paid, in whole years, at the same rate as registration (decision
    // 0009). This is the line that compounds, and the only one that does. It stays
    // permissionless: anyone may renew anyone's name, they simply have to pay for it.
    //
    // The extension runs from the old expiry, not from now, so renewing early neither
    // costs more nor loses the time already bought.
    let extension = o.expired_at().saturating_sub(i.expired_at());
    let years = years_for_term(extension);
    if years > MAX_TERM_YEARS {
        return Err(Error::TermTooLong);
    }
    require_treasury(apply_price_factor(registration_fee(o.account(), years), price_factor()?))?;

    // A sub-name must not outlive its parent (decision 0008). Register enforced this
    // and renew did not, which did not matter while every name ran to 2096. Now that
    // names genuinely expire, without this a child could renew past a parent that then
    // lapses and is recycled, leaving the child resolving under a name nobody holds.
    //
    // And it lives at the pleasure of whoever holds the parent, at creation AND at every
    // renewal (2026-09-17). Renewal of a child used to need nobody, like a plain name's,
    // so the holder of `shop.brand` could renew `brand` for its owner, which anyone may,
    // and then `shop.brand` for themselves, and keep the child alive through a change of
    // the parent's hands, a recycle and a stranger's fresh registration included. The
    // rule is now the one a person expects: the parent's owner keeps a sub-name alive or
    // lets it lapse, and a child cannot buy its own future. A plain name's renewal stays
    // permissionless; only the dotted label asks for a signature, the same one its
    // creation asked for.
    if let Some(parent) = parent_label(o.account()) {
        let pdata = require_parent(parent)?;
        let p = AccountData::parse(&pdata)?;
        if o.expired_at() > p.expired_at() {
            return Err(Error::ParentOutlived);
        }
        require_owner(p.owner_lock_hash())?;
    }
    Ok(())
}

/// Recycle: inputs `[p, x]`; output `[p']`. Splice x out of the list and prove it
/// is expired via an absolute-timestamp `since` (CKB consensus enforces timing).
fn validate_recycle(inputs: &[Cell], outputs: &[Cell]) -> Result<(), Error> {
    if inputs.len() != 2 || outputs.len() != 1 {
        return Err(Error::LinkedListBroken);
    }
    let a0 = AccountData::parse(&inputs[0].data)?;
    let a1 = AccountData::parse(&inputs[1].data)?;
    let p_out = AccountData::parse(&outputs[0].data)?;

    // The predecessor is the input whose id matches the surviving output.
    let (p_in, p_cell, x_in, x_cell) = if a0.id() == p_out.id() {
        (a0, &inputs[0], a1, &inputs[1])
    } else if a1.id() == p_out.id() {
        (a1, &inputs[1], a0, &inputs[0])
    } else {
        return Err(Error::LinkedListBroken);
    };

    // Splice: p'.next = x.next; p otherwise preserved byte-for-byte.
    if p_out.next() != x_in.next() {
        return Err(Error::LinkedListBroken);
    }
    if p_out.account() != p_in.account()
        || p_out.expired_at() != p_in.expired_at()
        || p_out.owner_lock_hash() != p_in.owner_lock_hash()
        || p_out.manager_lock_hash() != p_in.manager_lock_hash()
        || p_out.witness_hash() != p_in.witness_hash()
    {
        return Err(Error::StructuralDrift);
    }
    if lock_hash(p_cell, Source::Input)? != lock_hash(&outputs[0], Source::Output)? {
        return Err(Error::StructuralDrift);
    }
    capacity_not_reduced(p_cell, &outputs[0])?;
    // x must be p's *immediate* successor (SECURITY.md M-2: explicit, so recycle
    // stays correct even if the list were corrupted by another bug) and covered by
    // p's range, and genuinely expired.
    if x_in.id() != p_in.next() {
        return Err(Error::LinkedListBroken);
    }
    if !covers(&p_in.id(), &p_in.next(), &x_in.id()) {
        return Err(Error::LinkedListBroken);
    }
    // THE ROOT IS NOT A NAME. It is the sentinel that owns id zero, and its owning
    // id zero is what keeps id zero out of every live node's range. Recycling it
    // leaves a ring that covers the whole space, id zero included, and the next
    // register can then mint a cell with id zero and any label it likes.
    //
    // `covers` happily admits it: for the last node, `(lo, hi] = (max, 0]`, and the
    // upper endpoint IS the root's id. The expiry proof does not stop it either,
    // because the root is created with `expired_at = 0`, so it counts as expired
    // from the first block.
    if x_in.id() == ROOT_ID {
        return Err(Error::RootNotRecyclable);
    }
    require_expired_since(x_cell.index, x_in.expired_at())
}

// --- helpers ----------------------------------------------------------------

fn one_in_one_out<'a>(i: &'a [Cell], o: &'a [Cell]) -> Result<(&'a Cell, &'a Cell), Error> {
    if i.len() != 1 || o.len() != 1 {
        return Err(Error::StructuralDrift);
    }
    Ok((&i[0], &o[0]))
}

/// id, next and the account label must be byte-identical between input and output.
fn core_fields_unchanged(a: &AccountData, b: &AccountData) -> Result<(), Error> {
    if a.id() != b.id() || a.next() != b.next() || a.account() != b.account() {
        return Err(Error::StructuralDrift);
    }
    Ok(())
}

/// The predecessor `p -> p'` must be preserved byte-for-byte except its `next`
/// pointer: witness_hash, expiry, owner and account in `data`, plus the cell's
/// lock and capacity. Pointer rewiring is checked by the caller. This is the
/// invariant that lets a stranger spend someone else's predecessor cell safely.
fn predecessor_preserved(
    p_cell: &Cell,
    p: &AccountData,
    p_new_cell: &Cell,
    p_new: &AccountData,
) -> Result<(), Error> {
    if p_new.expired_at() != p.expired_at()
        || p_new.owner_lock_hash() != p.owner_lock_hash()
        || p_new.manager_lock_hash() != p.manager_lock_hash()
        || p_new.account() != p.account()
        || p_new.witness_hash() != p.witness_hash()
    {
        return Err(Error::StructuralDrift);
    }
    if lock_hash(p_cell, Source::Input)? != lock_hash(p_new_cell, Source::Output)? {
        return Err(Error::StructuralDrift);
    }
    // Capacity must not shrink, a stranger cannot skim the predecessor's CKB.
    let cap_in = load_cell_capacity(p_cell.index, Source::Input).map_err(|_| Error::Encoding)?;
    let cap_out =
        load_cell_capacity(p_new_cell.index, Source::Output).map_err(|_| Error::Encoding)?;
    if cap_out < cap_in {
        return Err(Error::StructuralDrift);
    }
    Ok(())
}

/// Reject an all-zero `owner_lock_hash` (SECURITY.md L-1): no real lock hashes to
/// zero, so this value can only be a mistake that makes the name permanently
/// un-editable/un-transferable. (The root sentinel's zero owner is set at genesis,
/// never via register/transfer, so it is unaffected.)
fn reject_null_owner(owner_lock_hash: &[u8]) -> Result<(), Error> {
    if owner_lock_hash.iter().all(|&b| b == 0) {
        return Err(Error::NullOwner);
    }
    Ok(())
}

/// Reject an authority that anyone can satisfy.
///
/// Every AccountCell's own lock is `account-lock`, an always-success script: that is
/// the whole design, with all authorization moved into this type script. So an
/// `owner_lock_hash` (or `manager_lock_hash`) set to THAT hash is satisfied by any
/// transaction that merely touches an AccountCell, because `require_owner` looks for
/// an input carrying that lock and every AccountCell carries it. The predecessor
/// `register` spends is one. The very cell being edited is another.
///
/// A name in that state is public property: anyone can edit its records, anyone can
/// transfer it away, and anyone can create sub-names under it. Nothing legitimate
/// ever wants this value, since an always-success script belongs to nobody, so it is
/// refused rather than left as a foot-gun. This closes the half of SECURITY.md L-1
/// that `reject_null_owner` did not: it only ever rejected all-zero.
fn reject_cell_lock_authority(hash: &[u8], cell_lock: &[u8; 32]) -> Result<(), Error> {
    // The stored identity is twenty bytes and the cell lock's hash is thirty-two. A
    // whole-slice compare could never be equal, so under truncation this guard failed
    // OPEN and an owner set to the always-success prefix was accepted, which with
    // `require_owner` matching prefixes made such a name public property.
    if hash == &cell_lock[..OWNER_HASH_LEN] {
        return Err(Error::OwnerIsCellLock);
    }
    Ok(())
}

/// Find the parent AccountCell among the cell deps and return its parsed data.
///
/// It must carry **this** type script (so it is a real AccountCell of this namespace,
/// not a look-alike) and its label must equal `parent` exactly. Uniqueness of labels is
/// the linked list's invariant, so at most one live cell can ever match.
fn require_parent(parent: &[u8]) -> Result<Vec<u8>, Error> {
    let self_hash = load_script_hash().map_err(|_| Error::Encoding)?;
    let mut i = 0;
    loop {
        match load_cell_type_hash(i, Source::CellDep) {
            Ok(opt) => {
                if opt.as_ref() == Some(&self_hash) {
                    let data = load_cell_data(i, Source::CellDep)
                        .map_err(|_| Error::MalformedAccountData)?;
                    if AccountData::parse(&data)?.account() == parent {
                        return Ok(data); // owned: AccountData borrows it, so the caller parses
                    }
                }
                i += 1;
            }
            Err(SysError::IndexOutOfBound) => return Err(Error::ParentMissing),
            Err(_) => return Err(Error::Encoding),
        }
    }
}

/// Owner authorization: the tx must spend at least one cell whose lock hash equals
/// the account's `owner_lock_hash` (auth delegated to the owner's wallet lock).
fn require_owner(owner_lock_hash: &[u8]) -> Result<(), Error> {
    for h in QueryIter::new(load_cell_lock_hash, Source::Input) {
        if h[..OWNER_HASH_LEN] == *owner_lock_hash {
            return Ok(());
        }
    }
    Err(Error::Unauthorized)
}

/// Edit authorization: the tx must spend a cell under **either** the owner's or the
/// manager's lock. The manager (a v2 delegate) may edit records but nothing else.
fn require_owner_or_manager(owner_lock_hash: &[u8], manager_lock_hash: &[u8]) -> Result<(), Error> {
    for h in QueryIter::new(load_cell_lock_hash, Source::Input) {
        if h[..OWNER_HASH_LEN] == *owner_lock_hash || h[..OWNER_HASH_LEN] == *manager_lock_hash {
            return Ok(());
        }
    }
    Err(Error::Unauthorized)
}

/// The recycle tx must set the target's input `since` to an absolute-timestamp
/// `>= expired_at + grace`. CKB consensus only admits the tx after that time.
fn require_expired_since(index: usize, expired_at: u64) -> Result<(), Error> {
    let input = load_input(index, Source::Input).map_err(|_| Error::Encoding)?;
    let since: u64 = input.since().unpack();
    const ABS_TIMESTAMP_FLAG: u64 = 0x40; // relative=0, metric=timestamp
    if (since >> 56) != ABS_TIMESTAMP_FLAG {
        return Err(Error::NotExpired);
    }
    let ts = since & 0x00FF_FFFF_FFFF_FFFF;
    if ts < expired_at.saturating_add(GRACE_SECONDS) {
        return Err(Error::NotExpired);
    }
    Ok(())
}

// --- genesis singleton (SPEC §9) -------------------------------------------
//
// A type script cannot see global state, so root uniqueness is enforced by
// requiring genesis to consume the one-time **genesis-token**: an input whose
// type-script hash equals this script's args (the namespace id). The token is a
// type-id cell, globally unique and unrecreatable, so it cannot be forged and is
// spendable exactly once. There is no ConfigCell, so nothing to forge (H-1 fix).
// Registration stays permissionless (it never reads any config).

/// This script's args = the namespace id = the first twenty bytes of the
/// genesis-token cell's type hash (decision 0015).
fn namespace_id() -> Result<[u8; NAMESPACE_LEN], Error> {
    let script = load_script().map_err(|_| Error::Encoding)?;
    let raw = script.args().raw_data();
    if raw.len() < NAMESPACE_LEN {
        return Err(Error::Encoding);
    }
    let mut h = [0u8; NAMESPACE_LEN];
    h.copy_from_slice(&raw[..NAMESPACE_LEN]);
    Ok(h)
}

/// The genesis tx must consume the one-time genesis-token, an input whose
/// type-script hash equals the namespace id. Being a type-id cell it can never be
/// recreated, so genesis runs exactly once and cannot be forged.
fn require_genesis_token(token_type_hash: &[u8; NAMESPACE_LEN]) -> Result<(), Error> {
    let mut i = 0;
    loop {
        match load_cell_type_hash(i, Source::Input) {
            Ok(Some(h)) if h[..NAMESPACE_LEN] == token_type_hash[..] => return Ok(()),
            Ok(_) => i += 1,
            Err(SysError::IndexOutOfBound) => return Err(Error::GenesisSeedMissing),
            Err(_) => return Err(Error::Encoding),
        }
    }
}
