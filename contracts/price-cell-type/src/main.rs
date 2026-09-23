//! `price-cell-type`, the price tag on registration (decision 0014).
//!
//! The registration fee in `cells-core` is a ceiling, hash-verified with the rest
//! of the contract. This script governs the one cell that may discount it. It has
//! two jobs, and nothing else:
//!
//! **Be unforgeable.** On creation the script's args must equal
//! `blake2b(first input ‖ output index)`, the construction CKB's own type-id uses,
//! which no other transaction can reproduce. So exactly one cell can ever carry a
//! given instance of this script, and `account-cell-type`, which is compiled with
//! that instance's hash, cannot be handed a look-alike. This closes the hole that
//! removed the old ConfigCell (SECURITY.md H-1: it matched *any* instance).
//!
//! **Bound every change.** Cell-dep scripts do not execute, so the rules cannot live
//! in `account-cell-type`; they live here and run whenever the cell is spent:
//!   * exactly one price cell out, and on update exactly one in (never destroyed,
//!     never duplicated);
//!   * lock unchanged and capacity not reduced, so a stolen key cannot strand it;
//!   * data is `version ‖ u32 basis points` inside `[PRICE_FACTOR_MIN, PRICE_FACTOR_MAX]`;
//!   * the factor moves by at most a sixteenth per update;
//!   * the input's `since` is a relative-timestamp of at least six hours. The cell's age
//!     *is* the time since the last update, because every update recreates it, and
//!     consensus refuses the block early. No clock, no header, no self-attestation.
//!
//! What this cannot do, said plainly: it cannot raise the fee above the ceiling (the
//! read side clamps), and it does not protect against a stolen key walking the price
//! to the floor over a fortnight. That is the deliberate trade in 0014: the floor is
//! a brick-guard, the step and the cooldown are what make theft slow and visible. The
//! pair went from a day and a quarter to six hours and a sixteenth on 2026-09-12: the
//! same ceiling per day, in four moves rather than one, so the honest keeper can keep
//! up with the coin.
#![no_std]
#![no_main]

use cells_core::{ckb_blake2b256, parse_price_factor, price_step_ok, PRICE_COOLDOWN_SECS};
use ckb_std::{
    ckb_constants::Source,
    ckb_types::prelude::{Entity, Unpack},
    error::SysError,
    high_level::{
        load_cell_capacity, load_cell_data, load_cell_lock_hash, load_cell_type_hash, load_input,
        load_script, load_script_hash,
    },
};

ckb_std::entry!(program_entry);
ckb_std::default_alloc!();

/// A packed `CellInput`: since (8) ‖ tx hash (32) ‖ index (4).
const CELL_INPUT_LEN: usize = 44;
/// relative = 1 (0x80) | metric = timestamp (0x40), the top byte of `since`.
const REL_TIMESTAMP_FLAG: u64 = 0xC0;

#[repr(i8)]
enum Err {
    Encoding = 1,
    /// Created with args that are not this transaction's type-id.
    BadArgs = 2,
    /// Not exactly one price cell out, or (on update) not exactly one in.
    Arity = 3,
    LockChanged = 4,
    CapacityShrunk = 5,
    /// Data is not `version ‖ u32 basis points` inside the band.
    BadData = 6,
    /// The factor moved by more than a quarter.
    Step = 7,
    /// The input's `since` is not a relative-timestamp of at least a day.
    Cooldown = 8,
}

pub fn program_entry() -> i8 {
    match run() {
        Ok(()) => 0,
        Err(e) => e as i8,
    }
}

/// The first cell on `source` carrying this script, and how many do.
fn find(source: Source, self_hash: &[u8; 32]) -> Result<(Option<usize>, usize), Err> {
    let mut first = None;
    let mut n = 0usize;
    let mut i = 0usize;
    loop {
        match load_cell_type_hash(i, source) {
            Ok(Some(h)) if &h == self_hash => {
                if first.is_none() {
                    first = Some(i);
                }
                n += 1;
                i += 1;
            }
            Ok(_) => i += 1,
            Err(SysError::IndexOutOfBound) => break,
            Err(_) => return Err(Err::Encoding),
        }
    }
    Ok((first, n))
}

fn run() -> Result<(), Err> {
    let self_hash = load_script_hash().map_err(|_| Err::Encoding)?;
    let (out, n_out) = find(Source::Output, &self_hash)?;
    let (inp, n_in) = find(Source::Input, &self_hash)?;

    // Exactly one price cell leaves the transaction: never two, and never none.
    if n_out != 1 {
        return Err(Err::Arity);
    }
    let out = out.ok_or(Err::Arity)?;
    let new_data = load_cell_data(out, Source::Output).map_err(|_| Err::Encoding)?;
    let new = parse_price_factor(&new_data).ok_or(Err::BadData)?;

    if n_in == 0 {
        // Creation. args == blake2b(first input ‖ output index as u64 LE): the type-id
        // construction. The first input is spent by this transaction, so no other
        // transaction can ever produce the same args.
        let script = load_script().map_err(|_| Err::Encoding)?;
        let args = script.args().raw_data();
        let first = load_input(0, Source::Input).map_err(|_| Err::Encoding)?;
        let fb = first.as_slice();
        if fb.len() != CELL_INPUT_LEN {
            return Err(Err::Encoding);
        }
        let mut buf = [0u8; CELL_INPUT_LEN + 8];
        buf[..CELL_INPUT_LEN].copy_from_slice(fb);
        buf[CELL_INPUT_LEN..].copy_from_slice(&(out as u64).to_le_bytes());
        let want = ckb_blake2b256(&buf);
        if args.len() != 32 || args[..] != want[..] {
            return Err(Err::BadArgs);
        }
        return Ok(());
    }

    // Update: one in, one out, same lock, no less capacity, a small step, not too soon.
    if n_in != 1 {
        return Err(Err::Arity);
    }
    let inp = inp.ok_or(Err::Arity)?;
    let lock_in = load_cell_lock_hash(inp, Source::Input).map_err(|_| Err::Encoding)?;
    let lock_out = load_cell_lock_hash(out, Source::Output).map_err(|_| Err::Encoding)?;
    if lock_in != lock_out {
        return Err(Err::LockChanged);
    }
    let cap_in = load_cell_capacity(inp, Source::Input).map_err(|_| Err::Encoding)?;
    let cap_out = load_cell_capacity(out, Source::Output).map_err(|_| Err::Encoding)?;
    if cap_out < cap_in {
        return Err(Err::CapacityShrunk);
    }
    let old_data = load_cell_data(inp, Source::Input).map_err(|_| Err::Encoding)?;
    let old = parse_price_factor(&old_data).ok_or(Err::BadData)?;
    if !price_step_ok(old, new) {
        return Err(Err::Step);
    }
    let since: u64 = load_input(inp, Source::Input)
        .map_err(|_| Err::Encoding)?
        .since()
        .unpack();
    if (since >> 56) != REL_TIMESTAMP_FLAG || (since & 0x00FF_FFFF_FFFF_FFFF) < PRICE_COOLDOWN_SECS {
        return Err(Err::Cooldown);
    }
    Ok(())
}
