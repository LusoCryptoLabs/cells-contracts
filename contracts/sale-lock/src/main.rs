//! `sale-lock`, an offer to sell a `.cell` name (decision 0012).
//!
//! Selling a name is a swap between two people who have never met, and neither
//! should have to trust the other or be online at the same time. On CKB that needs
//! no escrow and no marketplace: it needs a lock that anybody can satisfy by paying.
//!
//! **How a sale works.** `account-cell-type` authorizes `transfer` by requiring the
//! transaction to spend a cell under the name's `owner_lock_hash`. So the seller
//! lists by transferring the name's ownership to *this* lock and leaving one small
//! cell under it, the offer. A buyer spends that offer cell, which runs this script,
//! and in the same transaction takes the name. The type script sees a valid owner
//! authorization; this script sees the seller paid. Neither knows about the other,
//! and there is no moment where one side holds both the name and the money.
//!
//! **args** = `seller_lock_hash (32) ‖ price (8, little-endian shannons)`.
//!
//! Because the price lives in the args, it lives in the lock hash, and the lock hash
//! is what the name's data records as its owner. So the asking price is committed on
//! chain at listing and cannot be changed by anyone, seller included, without an
//! act that the seller has to sign.
//!
//! **Two ways to unlock:**
//!   1. the seller is here (some input sits under `seller_lock_hash`), which is how
//!      a listing is cancelled or the price changed;
//!   2. the outputs pay the asking price, split between the treasury (`sale_fee`: 1%,
//!      a flat 63 CKB cell from 630 to 6,300, nothing below 630) and the seller. The
//!      share comes out of the seller's proceeds and never on top of the price, so a
//!      name listed at ten thousand is bought for ten thousand and the seller gets 9,900.
//!
//! **Summing is the part that is easy to get wrong.** One payment must not settle two
//! offers. Counting inputs under *this exact* script hash defends same-price listings
//! but not two prices by one seller (different hashes, shared outputs). So every
//! instance sums what is owed over ALL of the seller's offer inputs, each at its own
//! price, and demands that total. Every instance sees every input, so they agree, and
//! the total cannot be split. Payment must be a PURE cell, or a hostile type script on
//! the payout would meet the capacity while the funds were not the seller's to spend.
#![no_std]
#![no_main]

use cells_core::{sale_fee, TREASURY_LOCK_HASH};
use ckb_std::{
    ckb_constants::Source,
    ckb_types::prelude::Entity,
    error::SysError,
    high_level::{
        load_cell_capacity, load_cell_lock, load_cell_lock_hash, load_cell_type, load_script,
    },
};

ckb_std::entry!(program_entry);
ckb_std::default_alloc!();

/// 32-byte seller lock hash, then 8 bytes of price.
const ARGS_LEN: usize = 40;

#[repr(i8)]
enum Err {
    Encoding = 1,
    BadArgs = 2,
    /// The seller is not here and the outputs do not pay the seller's share.
    Unpaid = 3,
    /// The seller's share was paid but the protocol's was not.
    FeeUnpaid = 4,
}

pub fn program_entry() -> i8 {
    match run() {
        Ok(()) => 0,
        Err(e) => e as i8,
    }
}

fn run() -> Result<(), Err> {
    let script = load_script().map_err(|_| Err::Encoding)?;
    let args = script.args().raw_data();
    if args.len() != ARGS_LEN {
        return Err(Err::BadArgs);
    }
    let seller: [u8; 32] = args[..32].try_into().map_err(|_| Err::BadArgs)?;
    let price = u64::from_le_bytes(args[32..40].try_into().map_err(|_| Err::BadArgs)?);

    // 1. The seller is in this transaction, so it is theirs to do as they like:
    //    cancel the listing, or take the name back and list it again at another
    //    price. A seller can always get out, which is what makes listing safe, and
    //    it is also the only way to reclaim a mistaken zero-price offer cell.
    if any_input_under(&seller)? {
        return Ok(());
    }

    // A listing must ask a positive price. At zero the split is zero and a stranger
    // would unlock with no outputs at all, taking the name for nothing. (The seller
    // path above still lets the owner reclaim such an offer.)
    if price == 0 {
        return Err(Err::BadArgs);
    }

    // 2. Otherwise the price has to be paid, split: the treasury's share (decision
    //    0012) comes out of the seller's proceeds, never on top of the price.
    //
    //    Sum what is owed over EVERY offer input belonging to this seller, each at its
    //    OWN price. Two listings by one seller at different prices are different lock
    //    hashes, so a per-instance `price * count(my exact hash)` let one payment for
    //    the dearer listing satisfy the cheaper ones (their offer cells consumed free).
    //    Summing over all of the seller's offers makes every instance demand the same
    //    total, which cannot be split. Every instance sees every input, so they agree.
    let my_code = script.code_hash();
    let my_htype: u8 = script.hash_type().into();
    let (owed_seller, _) = owed_over_offers(Some(&seller), my_code.as_slice(), my_htype)?;
    // The seller's leg is per seller, because each seller's payout is under their own
    // lock and cannot be shared. The treasury's leg is not: every instance in this
    // transaction reads the SAME treasury outputs, so a per-seller total let one
    // fee-sized output answer two sellers at once, each instance seeing enough for
    // itself and nobody seeing the sum. Summed over every offer here, each instance
    // demands the same indivisible figure, which is the fix already applied one level
    // down for two listings by one seller.
    let (_, owed_treasury) = owed_over_offers(None, my_code.as_slice(), my_htype)?;
    // Only PURE outputs count as payment. Without this a buyer could attach a hostile
    // type script (a Nervos DAO lockup, a joint-custody type) to the seller's or the
    // treasury's output, meeting the capacity while the funds are not actually theirs
    // to spend, an extortion lever. A real payment is an ordinary cell.
    if paid_to_pure(&seller)? < owed_seller {
        return Err(Err::Unpaid);
    }
    // A seller who IS the treasury owes itself nothing: the same outputs answer both
    // sums, so the requirement collapses to the seller's share. That is the treasury
    // selling its own name, and paying oneself is a no-op.
    if paid_to_pure(&TREASURY_LOCK_HASH)? < owed_treasury {
        return Err(Err::FeeUnpaid);
    }
    Ok(())
}

fn any_input_under(lock_hash: &[u8; 32]) -> Result<bool, Err> {
    let mut i = 0usize;
    loop {
        match load_cell_lock_hash(i, Source::Input) {
            Ok(h) => {
                if &h == lock_hash {
                    return Ok(true);
                }
                i += 1;
            }
            Err(SysError::IndexOutOfBound) => return Ok(false),
            Err(_) => return Err(Err::Encoding),
        }
    }
}

/// Total owed to the seller and to the treasury across the offer inputs in this
/// transaction that are sale locks (same code), each priced by its OWN args.
///
/// `seller = Some(hash)` counts only that seller's offers, which is what their payout
/// leg needs. `seller = None` counts every offer in the transaction, which is what the
/// treasury's leg needs, because all instances share the treasury's outputs.
fn owed_over_offers(seller: Option<&[u8; 32]>, my_code: &[u8], my_htype: u8) -> Result<(u64, u64), Err> {
    let mut owed_seller: u64 = 0;
    let mut owed_treasury: u64 = 0;
    let mut i = 0usize;
    loop {
        match load_cell_lock(i, Source::Input) {
            Ok(lock) => {
                let code = lock.code_hash();
                let htype: u8 = lock.hash_type().into();
                let a = lock.args().raw_data();
                // For the treasury's leg, an offer whose seller is present owes nothing:
                // that seller is cancelling or relisting, not selling, and their own
                // instances return early on the same predicate. Counting it made a
                // cancellation beside a purchase demand a fee on a name that was not
                // sold (pass 7, P7-2). Every instance evaluates the same inputs, so they
                // still agree on one indivisible figure and F-5 stays closed.
                let mine = match seller {
                    Some(h) => &a.len() == &ARGS_LEN && &a[..32] == &h[..],
                    None => a.len() == ARGS_LEN && !any_input_under(a[..32].try_into().map_err(|_| Err::BadArgs)?)?,
                };
                if code.as_slice() == my_code && htype == my_htype && a.len() == ARGS_LEN && mine {
                    let p = u64::from_le_bytes(a[32..40].try_into().map_err(|_| Err::BadArgs)?);
                    let f = sale_fee(p);
                    // The offer cell's own capacity goes back to the seller, on top of the
                    // price. It is the seller's money, parked to publish the listing, and
                    // until 2026-09-14 whoever completed the sale kept it, justified as
                    // "roughly what the transaction costs them". Measured on Pudge that
                    // day: the deposit is 160 CKB and the transaction costs 0.00002, which
                    // is wrong by a factor of eight million. It did not show while the
                    // cheapest listing was 630 CKB, because the taker still had to bring
                    // 470 of their own. At 63 it showed at once: a name was bought with
                    // **no input from the buyer at all**, who took the name and 97 CKB of
                    // the seller's deposit with it, while the seller "received" 63 and was
                    // 97 down. Returning it makes the buyer bring exactly the price and
                    // the seller receive exactly the price, which is what both were told.
                    let deposit = load_cell_capacity(i, Source::Input).map_err(|_| Err::Encoding)?;
                    owed_seller = owed_seller.saturating_add(p.saturating_sub(f)).saturating_add(deposit);
                    owed_treasury = owed_treasury.saturating_add(f);
                }
                i += 1;
            }
            Err(SysError::IndexOutOfBound) => return Ok((owed_seller, owed_treasury)),
            Err(_) => return Err(Err::Encoding),
        }
    }
}

/// What the PURE outputs (no type script) pay to a lock. The offer cell's own capacity
/// is not counted here as a payment, because it is an input under the sale lock rather
/// than an output: `owed_over_offers` adds it to what the seller is owed instead, so it
/// comes back to them in the same transaction that sells the name.
fn paid_to_pure(lock_hash: &[u8; 32]) -> Result<u64, Err> {
    let mut paid: u64 = 0;
    let mut i = 0usize;
    loop {
        match load_cell_lock_hash(i, Source::Output) {
            Ok(h) => {
                if &h == lock_hash {
                    let typed = load_cell_type(i, Source::Output).map_err(|_| Err::Encoding)?;
                    if typed.is_none() {
                        let c =
                            load_cell_capacity(i, Source::Output).map_err(|_| Err::Encoding)?;
                        paid = paid.saturating_add(c);
                    }
                }
                i += 1;
            }
            Err(SysError::IndexOutOfBound) => return Ok(paid),
            Err(_) => return Err(Err::Encoding),
        }
    }
}
