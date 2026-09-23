//! The sale lock, checked as a **property** over a grid rather than as a list of cases.
//!
//! Why this file exists. On 2026-09-14 the worst defect of the day, F-8, went through 171
//! contract tests and eight review passes without being seen. It was found by arithmetic
//! on a real transaction: the buyer's wallet contributed nothing, they took the name and
//! 97 CKB, and the seller was 97 down. Twenty-four hand-written cases all passed, because
//! every one of them described a sale somebody had already imagined.
//!
//! A case test asks "does this transaction behave?". A property test asks "is there **any**
//! transaction in this space that behaves wrongly?", which is a different question and the
//! one an attacker asks. The space here is small enough to enumerate exactly, so nothing is
//! random and nothing needs a seed: every combination of a price and what each party is
//! paid, over a grid chosen to straddle every edge the schedule has.
//!
//! The property, stated once:
//!
//! > The lock accepts a purchase **if and only if** the seller receives at least
//! > `price - fee + deposit` and the treasury receives at least `fee`.
//!
//! An "if and only if" is what makes this worth running. The old contract satisfied the
//! "only if" perfectly: everything it accepted paid the seller the price. What it failed
//! was the "if", in the other direction, by accepting transactions that paid the seller
//! the price out of the seller's own deposit. One assertion over a grid finds that; no
//! number of examples reliably does.

use ckb_testtool::builtin::ALWAYS_SUCCESS;
use ckb_testtool::ckb_types::{bytes::Bytes, core::ScriptHashType, core::TransactionBuilder, packed::*, prelude::*};
use ckb_testtool::context::Context;
use tests::Loader;

const MAX_CYCLES: u64 = 100_000_000;
const CKB: u64 = 100_000_000;
const OFFER_CAP: u64 = 100 * CKB;

/// Prices that straddle every edge of the fee schedule: under the waiver, at its step,
/// inside the flat-cell band, where the rate takes over, and far above it. Also two
/// prices below the deposit, which is the region F-8 lived in.
const PRICES: [u64; 9] = [
    61 * CKB,    // the listing floor, well under the deposit
    100 * CKB,   // the F-8 case exactly
    629 * CKB,   // one below the fee step
    630 * CKB,   // the step: a flat cell becomes payable
    1_000 * CKB, // inside the flat band
    6_299 * CKB, // one below where the rate takes over
    6_300 * CKB, // the two bands meet
    10_000 * CKB,
    50_000 * CKB,
];

/// What the transaction pays each party, as an offset from what is owed. Zero is exact;
/// negative is short by that many shannons; positive is generous.
const OFFSETS: [i64; 5] = [-(100 * CKB as i64), -1, 0, 1, 100 * CKB as i64];

/// One purchase: a single offer at `price`, paying the seller and the treasury the given
/// amounts. Returns whether the deployed lock accepted it.
fn purchase(price: u64, to_seller: u64, to_treasury: u64) -> bool {
    let mut ctx = Context::default();
    let sale_op = ctx.deploy_cell(Loader::default().load_binary("sale-lock"));
    let plain_op = ctx.deploy_cell(ALWAYS_SUCCESS.clone());

    let seller_lock = ctx.build_script(&plain_op, Bytes::from_static(b"seller")).expect("seller");
    let buyer_lock = ctx.build_script(&plain_op, Bytes::from_static(b"buyer")).expect("buyer");
    // Data1 and these exact args, so the treasury hashes the same on every run and matches
    // what the test build of the lock was compiled against (src/bin/treasury-hash.rs).
    let treasury_lock = ctx
        .build_script_with_hash_type(&plain_op, ScriptHashType::Data1, Bytes::from_static(b"treasury"))
        .expect("treasury");

    let mut args = seller_lock.calc_script_hash().raw_data().to_vec();
    args.extend_from_slice(&price.to_le_bytes());
    let sale_lock = ctx
        .build_script_with_hash_type(&sale_op, ScriptHashType::Data1, Bytes::from(args))
        .expect("sale script");

    // The offer cell carries the seller's lock script in its data so a buyer can pay them.
    let offer_out = ctx.create_cell(
        CellOutput::new_builder()
            .capacity(OFFER_CAP.pack())
            .lock(sale_lock.clone())
            .build(),
        Bytes::from(seller_lock.as_slice().to_vec()),
    );
    // Something of the buyer's, so the transaction has a payer at all.
    let buyer_out = ctx.create_cell(
        CellOutput::new_builder()
            .capacity((1_000_000 * CKB).pack())
            .lock(buyer_lock.clone())
            .build(),
        Bytes::new(),
    );

    let mut outputs = vec![CellOutput::new_builder()
        .capacity(to_seller.pack())
        .lock(seller_lock)
        .build()];
    let mut data = vec![Bytes::new()];
    if to_treasury > 0 {
        outputs.push(
            CellOutput::new_builder()
                .capacity(to_treasury.pack())
                .lock(treasury_lock)
                .build(),
        );
        data.push(Bytes::new());
    }

    let tx = TransactionBuilder::default()
        .input(CellInput::new_builder().previous_output(offer_out).build())
        .input(CellInput::new_builder().previous_output(buyer_out).build())
        .outputs(outputs)
        .outputs_data(data.pack())
        .build();
    let tx = ctx.complete_tx(tx);
    ctx.verify_tx(&tx, MAX_CYCLES).is_ok()
}

/// What an honest purchase owes, from the contract's own function.
fn owed(price: u64) -> (u64, u64) {
    let fee = cells_core::sale_fee(price);
    (price - fee + OFFER_CAP, fee)
}

#[test]
fn the_lock_accepts_a_purchase_exactly_when_both_legs_are_paid() {
    let mut checked = 0;
    let mut wrong = Vec::new();
    for price in PRICES {
        let (owed_seller, owed_treasury) = owed(price);
        for ds in OFFSETS {
            for dt in OFFSETS {
                let to_seller = (owed_seller as i64 + ds).max(0) as u64;
                let to_treasury = (owed_treasury as i64 + dt).max(0) as u64;
                // A treasury leg of zero when zero is owed is the honest shape, and the
                // harness omits the output entirely for it.
                let should = to_seller >= owed_seller && to_treasury >= owed_treasury;
                let did = purchase(price, to_seller, to_treasury);
                checked += 1;
                if did != should {
                    wrong.push(format!(
                        "price {} seller {} (owed {}) treasury {} (owed {}): contract {}, rule says {}",
                        price / CKB,
                        to_seller / CKB,
                        owed_seller / CKB,
                        to_treasury / CKB,
                        owed_treasury / CKB,
                        if did { "accepted" } else { "refused" },
                        if should { "accept" } else { "refuse" },
                    ));
                }
            }
        }
    }
    assert!(
        wrong.is_empty(),
        "{} of {checked} combinations disagree with the rule:\n  {}",
        wrong.len(),
        wrong.join("\n  ")
    );
    // The control on the grid itself: a property that never exercised a refusal would
    // pass against a lock that accepts everything.
    assert!(checked >= 200, "only {checked} combinations; the grid has shrunk");
}

#[test]
fn no_purchase_the_lock_accepts_leaves_the_seller_worse_off() {
    // The F-8 property, stated as the thing that actually went wrong rather than as a
    // rule about legs. The seller parked OFFER_CAP to list; if the lock accepts a
    // purchase, what lands under the seller's lock has to be at least that much more
    // than nothing, or listing a name cost them money to give it away.
    for price in PRICES {
        let (owed_seller, owed_treasury) = owed(price);
        // Every payout from nothing up to what is owed, in steps, plus the exact figure.
        for n in 0..=10u64 {
            let to_seller = owed_seller * n / 10;
            if !purchase(price, to_seller, owed_treasury) {
                continue; // refused, which is the lock doing its job
            }
            assert!(
                to_seller >= OFFER_CAP,
                "at price {} the lock accepted a sale paying the seller {} CKB, \
                 less than the {} CKB deposit they parked to list it",
                price / CKB,
                to_seller / CKB,
                OFFER_CAP / CKB
            );
            assert!(
                to_seller >= price - cells_core::sale_fee(price),
                "at price {} the lock accepted a sale paying the seller less than the asking price",
                price / CKB
            );
        }
    }
}
