//! `account-lock`, the uniform lock on every AccountCell (Phase 2; decision 0002).
//!
//! It always succeeds. That is safe, and intentional, because a CKB **type**
//! script runs whenever its cell is consumed (input *and* output), so the
//! `account-cell-type` script is the sole, comprehensive guardian of every
//! AccountCell and cannot be bypassed:
//!
//!   * system actions (`register` / `renew` / `recycle`) are permissionless, and
//!     the type script preserves each spent predecessor byte-for-byte except its
//!     `next` pointer, so a stranger can do no harm;
//!   * owner actions (`edit_*` / `transfer`) are gated by the type script, which
//!     requires the tx to spend a cell under the account's `owner_lock_hash`.
//!
//! Keeping the lock uniform (no per-cell args) means every AccountCell shares one
//! lock hash, which the type script relies on when it checks that a predecessor's
//! lock is unchanged across a permissionless splice.
#![no_std]
#![no_main]

ckb_std::entry!(program_entry);
ckb_std::default_alloc!();

pub fn program_entry() -> i8 {
    0
}
