//! Integration tests for `sale-lock` (decision 0012; run `make build` first).
//!
//! The lock is what makes a name sellable to a stranger who is not online: it
//! unlocks for the seller, or for anybody who pays the asking price. Everything it
//! can get wrong is money, so each rule below has a case that fails when the rule
//! is removed.
//!
//! The type script's side of a sale needs no new test: `validate_transfer` asks only
//! that the transaction spend a cell under the name's `owner_lock_hash`, and it does
//! not care which lock that is. Spending the offer cell is exactly that, and
//! `transfer_changes_owner_ok` in `account_cell.rs` already covers it. What is new,
//! and what is tested here, is the lock.
use ckb_testtool::builtin::ALWAYS_SUCCESS;
use ckb_testtool::ckb_types::{
    bytes::Bytes,
    core::{ScriptHashType, TransactionBuilder},
    packed::{CellDep, CellInput, CellOutput, Script},
    prelude::*,
};
use ckb_testtool::context::Context;
use tests::Loader;

const MAX_CYCLES: u64 = 100_000_000;
/// The asking price in every fixture: 10,000 CKB. Above the floor the fee rate implies,
/// because the protocol's share has to exist as a cell of its own and a cell costs about
/// 63 CKB. A fixture priced below that would exercise arithmetic no real sale can reach.
const PRICE: u64 = 10_000 * 100_000_000;
/// The split at that price, taken from the contract's own function rather than written
/// out again here. When the rate moved from ten percent to one on 2026-09-14, eight of
/// these tests failed because the number was copied: a fixture that restates a rule
/// tests the copy.
const FEE: u64 = cells_core::sale_fee(PRICE);
/// What the seller must receive for one offer: the price, less the protocol's share,
/// **plus the deposit they parked in the offer cell**, which comes back to them on a
/// sale. Every fixture that completes a sale pays this, and eight of them failed when
/// the deposit started coming back, which is how a rule change should read.
const TO_SELLER: u64 = PRICE - FEE + OFFER_CAP;
const OFFER_CAP: u64 = 100 * 100_000_000; // what the seller leaves in the offer cell

fn assert_code(res: &Result<u64, String>, code: u8, what: &str) {
    let e = res.as_ref().err().unwrap_or_else(|| panic!("{what}: expected a failure, it passed"));
    assert!(e.contains(&format!("error code {code}")), "{what}: wanted error {code}, got {e}");
}

/// Who a cell belongs to. `Seller` and `Buyer` are ordinary wallets (always-success
/// with distinct args, so distinct lock hashes); `Offer` is the sale lock itself.
#[derive(Clone, Copy, PartialEq)]
enum W {
    Seller,
    Buyer,
    /// A second seller wallet, to prove one payment cannot satisfy another's lock.
    Other,
    /// The protocol's treasury (decision 0009), which takes a tenth of every sale.
    /// Its args must match `TREASURY_ARGS` in src/bin/treasury-hash.rs, which is what
    /// tells the test build of the lock which hash to expect.
    Treasury,
}

struct Case {
    /// Offer cells being spent, each with the price its args commit to.
    offers: Vec<u64>,
    /// Offer cells belonging to a SECOND seller, in the same transaction. Their own
    /// prices, their own lock hash, their own script instance: the case where two
    /// people sell at once and the treasury's tenth is owed on both.
    other_offers: Vec<u64>,
    /// Ordinary inputs, by owner.
    inputs: Vec<W>,
    /// Outputs, as (owner, capacity).
    outputs: Vec<(W, u64)>,
    /// Replace the 40-byte args with something else, to test the length check.
    bad_args: Option<Bytes>,
    /// Whose lock hash the offers name as the seller.
    seller: W,
    /// Output indices that carry a (always-success) type script, so a hostile-typed
    /// payout can be tested: such an output is not a pure payment and must not count.
    typed_outputs: Vec<usize>,
}

impl Case {
    /// A buyer paying the asking price for one name, which is the whole point.
    fn buy() -> Case {
        Case {
            offers: vec![PRICE],
            other_offers: vec![],
            inputs: vec![W::Buyer],
            outputs: vec![(W::Seller, TO_SELLER), (W::Treasury, FEE)],
            bad_args: None,
            seller: W::Seller,
            typed_outputs: vec![],
        }
    }
}

fn run(c: Case) -> Result<u64, String> {
    let mut ctx = Context::default();
    let sale_op = ctx.deploy_cell(Loader::default().load_binary("sale-lock"));
    let plain_op = ctx.deploy_cell(ALWAYS_SUCCESS.clone());

    // Every script is built up front: `build_script` needs `&mut ctx`, so the
    // closures below have to be pure or the borrow checker refuses `create_cell`.
    let s_seller = ctx.build_script(&plain_op, Bytes::from_static(b"seller")).expect("seller");
    let s_buyer = ctx.build_script(&plain_op, Bytes::from_static(b"buyer")).expect("buyer");
    let s_other = ctx.build_script(&plain_op, Bytes::from_static(b"other")).expect("other");
    // Data1, so the treasury hashes the same on every run and can be compiled into
    // the lock. `build_script` uses the deployed cell's type-id hash, whose args
    // ckb-testtool randomises per Context. See src/bin/treasury-hash.rs.
    let s_treasury = ctx
        .build_script_with_hash_type(&plain_op, ScriptHashType::Data1, Bytes::from_static(b"treasury"))
        .expect("treasury");
    let wallet = |w: W| -> Script {
        match w {
            W::Seller => s_seller.clone(),
            W::Buyer => s_buyer.clone(),
            W::Other => s_other.clone(),
            W::Treasury => s_treasury.clone(),
        }
    };
    let mut seller_hash = [0u8; 32];
    seller_hash.copy_from_slice(&wallet(c.seller).calc_script_hash().as_bytes());
    let mut other_hash = [0u8; 32];
    other_hash.copy_from_slice(&wallet(W::Other).calc_script_hash().as_bytes());

    // args = seller lock hash ‖ price, so the price is part of the lock hash and
    // therefore part of what the name records as its owner.
    let offer_scripts: Vec<Script> = c
        .offers
        .iter()
        .map(|price| {
            let args = match &c.bad_args {
                Some(b) => b.clone(),
                None => {
                    let mut a = seller_hash.to_vec();
                    a.extend_from_slice(&price.to_le_bytes());
                    Bytes::from(a)
                }
            };
            ctx.build_script_with_hash_type(&sale_op, ScriptHashType::Data1, args).expect("sale lock")
        })
        .collect();

    // The second seller's offers, built the same way against their own hash.
    let other_scripts: Vec<Script> = c
        .other_offers
        .iter()
        .map(|price| {
            let mut a = other_hash.to_vec();
            a.extend_from_slice(&price.to_le_bytes());
            ctx.build_script_with_hash_type(&sale_op, ScriptHashType::Data1, Bytes::from(a)).expect("other sale lock")
        })
        .collect();

    let mut inputs: Vec<CellInput> = Vec::new();
    for script in offer_scripts.iter().chain(other_scripts.iter()) {
        let op = ctx.create_cell(
            CellOutput::new_builder().capacity(OFFER_CAP.pack()).lock(script.clone()).build(),
            Bytes::new(),
        );
        inputs.push(CellInput::new_builder().previous_output(op).build());
    }
    for w in &c.inputs {
        let op = ctx.create_cell(
            CellOutput::new_builder().capacity((PRICE * 4).pack()).lock(wallet(*w)).build(),
            Bytes::new(),
        );
        inputs.push(CellInput::new_builder().previous_output(op).build());
    }

    // An always-success TYPE script for the "hostile type on the payout" test. A payout
    // that carries a type script is not a pure cell, so the lock must not count it.
    let s_type = ctx
        .build_script_with_hash_type(&plain_op, ScriptHashType::Data1, Bytes::from_static(b"hostile-type"))
        .expect("type");
    let outputs: Vec<CellOutput> = c
        .outputs
        .iter()
        .enumerate()
        .map(|(i, (w, cap))| {
            let b = CellOutput::new_builder().capacity(cap.pack()).lock(wallet(*w));
            if c.typed_outputs.contains(&i) {
                b.type_(Some(s_type.clone()).pack()).build()
            } else {
                b.build()
            }
        })
        .collect();
    let outputs_data: Vec<Bytes> = c.outputs.iter().map(|_| Bytes::new()).collect();

    let tx = ctx.complete_tx(
        TransactionBuilder::default()
            .inputs(inputs)
            .outputs(outputs)
            .outputs_data(outputs_data.pack())
            .cell_dep(CellDep::new_builder().out_point(sale_op).build())
            .cell_dep(CellDep::new_builder().out_point(plain_op).build())
            .build(),
    );
    ctx.verify_tx(&tx, MAX_CYCLES).map_err(|e| format!("{e:?}"))
}

#[test]
fn a_stranger_may_buy_by_paying_the_asking_price() {
    let res = run(Case::buy());
    assert!(res.is_ok(), "paying the asking price must unlock the offer, got {res:?}");
}

#[test]
fn a_shannon_short_is_not_a_sale() {
    let res =
        run(Case { outputs: vec![(W::Seller, TO_SELLER - 1), (W::Treasury, FEE)], ..Case::buy() });
    assert_code(&res, 3, "the seller must be paid in full");
}

#[test]
fn paying_the_wrong_person_is_not_a_sale() {
    // The money has to reach the seller named in the args, not simply leave the buyer.
    let res = run(Case { outputs: vec![(W::Other, TO_SELLER), (W::Treasury, FEE)], ..Case::buy() });
    assert_code(&res, 3, "paying somebody else does not buy the name");
}

#[test]
fn the_protocol_takes_its_tenth() {
    // The seller is paid their whole share and the treasury nothing. This is the
    // fee, and it is the difference between a marketplace and a free one.
    let res = run(Case { outputs: vec![(W::Seller, TO_SELLER)], ..Case::buy() });
    assert_code(&res, 4, "a sale owes the treasury a tenth");
}

#[test]
fn the_protocol_fee_cannot_be_paid_short() {
    let res =
        run(Case { outputs: vec![(W::Seller, TO_SELLER), (W::Treasury, FEE - 1)], ..Case::buy() });
    assert_code(&res, 4, "a shannon short of the tenth is not the tenth");
}

#[test]
fn the_buyer_pays_the_asking_price_and_no_more() {
    // What the BUYER brings is the price and nothing else. The seller's payout is the
    // price less the fee plus their own deposit coming back, so the deposit passes
    // through the transaction without either side gaining or losing it: subtract it
    // again and the two shares are exactly the price.
    assert_eq!((TO_SELLER - OFFER_CAP) + FEE, PRICE);
    let res = run(Case { inputs: vec![W::Buyer], ..Case::buy() });
    assert!(res.is_ok(), "a buyer paying exactly the asking price must succeed, got {res:?}");
}

#[test]
fn the_seller_can_always_take_it_back() {
    // No payment at all, but the seller is spending a cell here. This is how a
    // listing is cancelled, and it is why listing is safe to do.
    let res = run(Case { inputs: vec![W::Seller], outputs: vec![], ..Case::buy() });
    assert!(res.is_ok(), "the seller must be able to cancel, got {res:?}");
}

#[test]
fn one_payment_cannot_buy_two_names() {
    // Two names listed by the same seller at the same price share one lock hash.
    // Without counting the offers, a single payment would take both.
    let res = run(Case { offers: vec![PRICE, PRICE], ..Case::buy() });
    assert_code(&res, 3, "two offers cost twice the price");
}

#[test]
fn two_names_bought_together_cost_both_prices() {
    let res = run(Case {
        offers: vec![PRICE, PRICE],
        outputs: vec![(W::Seller, TO_SELLER * 2), (W::Treasury, FEE * 2)],
        ..Case::buy()
    });
    assert!(res.is_ok(), "paying for both must work, got {res:?}");
}

#[test]
fn the_payment_may_arrive_in_pieces() {
    // Nothing pins an index or an output count: a wallet is free to split.
    let res = run(Case {
        outputs: vec![
            (W::Seller, TO_SELLER / 4),
            (W::Buyer, 500),
            (W::Seller, TO_SELLER - TO_SELLER / 4),
            (W::Treasury, FEE / 2),
            (W::Treasury, FEE - FEE / 2),
        ],
        ..Case::buy()
    });
    assert!(res.is_ok(), "a split payment is still a payment, got {res:?}");
}

#[test]
fn one_payment_cannot_sweep_a_cheaper_listing() {
    // Two listings by the same seller at DIFFERENT prices are different lock hashes.
    // The old per-hash multiplier let paying the dearer one satisfy the cheaper one,
    // consuming its offer cell for free. Summing over the seller's offers demands both.
    let dear = 2 * PRICE;
    let res = run(Case {
        offers: vec![PRICE, dear],
        // pay only for the dear listing
        outputs: vec![(W::Seller, dear - cells_core::sale_fee(dear) + OFFER_CAP), (W::Treasury, cells_core::sale_fee(dear))],
        ..Case::buy()
    });
    assert_code(&res, 3, "the cheaper listing must be paid for too");
}

#[test]
fn both_listings_at_different_prices_bought_together() {
    let dear = 2 * PRICE;
    let res = run(Case {
        offers: vec![PRICE, dear],
        outputs: vec![
            (W::Seller, TO_SELLER + (dear - cells_core::sale_fee(dear)) + OFFER_CAP),
            (W::Treasury, FEE + cells_core::sale_fee(dear)),
        ],
        ..Case::buy()
    });
    assert!(res.is_ok(), "paying both prices in full must work, got {res:?}");
}

#[test]
fn a_hostile_type_on_the_payout_is_not_a_payment() {
    // The seller's output meets the capacity but carries a type script (a DAO lockup,
    // a joint-custody type), so the funds are not the seller's to freely spend. Only a
    // pure cell counts, so this is refused as unpaid.
    let res = run(Case { typed_outputs: vec![0], ..Case::buy() });
    assert_code(&res, 3, "a typed payout does not count as paying the seller");
}

#[test]
fn a_hostile_type_on_the_treasury_output_is_not_the_fee() {
    let res = run(Case { typed_outputs: vec![1], ..Case::buy() });
    assert_code(&res, 4, "a typed treasury output does not count as the fee");
}

#[test]
fn a_stranger_cannot_take_a_zero_price_name() {
    // A zero-price sale lock would unlock with no outputs. A stranger is refused.
    let res = run(Case { offers: vec![0], inputs: vec![W::Buyer], outputs: vec![], ..Case::buy() });
    assert_code(&res, 2, "a zero-price listing does not unlock for a stranger");
}

#[test]
fn the_seller_can_still_reclaim_a_zero_price_offer() {
    // ...but the seller can always take it back, so a mistaken zero-price offer cell
    // is not stranded.
    let res = run(Case { offers: vec![0], inputs: vec![W::Seller], outputs: vec![], ..Case::buy() });
    assert!(res.is_ok(), "the seller must be able to reclaim a zero-price offer, got {res:?}");
}

#[test]
fn malformed_args_are_refused() {
    // A lock whose args are not exactly a hash and a price has no meaning, and
    // guessing one would be inventing a price nobody agreed to.
    let res = run(Case { bad_args: Some(Bytes::from_static(b"short")), ..Case::buy() });
    assert_code(&res, 2, "args must be a 32-byte seller and an 8-byte price");
}

#[test]
fn one_fee_cannot_settle_two_sellers() {
    // Two sellers, one transaction, neither of them present to cancel. Each offer's
    // script instance checks the treasury's outputs on its own, so a single fee-sized
    // output satisfies both unless what is owed to the treasury is summed over every
    // offer in the transaction rather than only this seller's. The buyer pays both
    // sellers in full; it is the protocol that is short.
    let mut c = Case::buy();
    c.other_offers = vec![PRICE];
    c.outputs = vec![(W::Seller, TO_SELLER), (W::Other, TO_SELLER), (W::Treasury, FEE)];
    let res = run(c);
    assert_code(&res, 4, "one fee cannot answer two sales");
}

/// The treasury leg (F-5) sums the tenth over EVERY offer input, including one whose
/// seller is present and is merely cancelling. So a cancellation beside a purchase
/// makes the purchase owe the treasury a fee on a name that was not sold. Fail-closed
/// and never built by the SDK, so functional rather than a hole; recorded so the
/// over-demand is a known shape and not a surprise for a marketplace batching both.
#[test]
fn a_cancellation_beside_a_purchase_does_not_owe_the_treasury_twice() {
    let mut c = Case::buy();
    c.other_offers = vec![PRICE]; // Other's listing, bought by Buyer
    c.inputs = vec![W::Seller, W::Buyer]; // Seller is here: their own offer is a cancel
    c.outputs = vec![(W::Other, TO_SELLER), (W::Treasury, FEE)]; // one sale, one fee
    let res = run(c);
    assert!(res.is_ok(), "a cancelled listing is not a sale and owes no fee, got {res:?}");
}

#[test]
fn two_sellers_paying_both_fees_is_a_sale() {
    // The control: the same transaction with the tenth paid on both names goes through,
    // so the rule above refuses underpayment rather than refusing two sellers.
    let mut c = Case::buy();
    c.other_offers = vec![PRICE];
    c.outputs = vec![(W::Seller, TO_SELLER), (W::Other, TO_SELLER), (W::Treasury, FEE * 2)];
    let res = run(c);
    assert!(res.is_ok(), "two sellers paying both fees must pass, got {res:?}");
}

/// The case the whole fee change was for: a name cheap enough that one percent of it
/// could not be a cell. Nothing is owed, no treasury output exists, and the seller is
/// paid the whole asking price. Before 2026-09-14 this transaction was impossible to
/// build, which meant a name could not be sold for less than about 6,300 CKB.
#[test]
fn a_cheap_name_is_sold_with_no_fee_at_all() {
    let cheap = 100 * 100_000_000; // 100 CKB; one percent is 1 CKB, a cell cannot be that small
    assert_eq!(cells_core::sale_fee(cheap), 0, "the fixture has to be below the threshold");
    let res = run(Case {
        offers: vec![cheap],
        outputs: vec![(W::Seller, cheap + OFFER_CAP)], // the whole price and the deposit back, no treasury output
        ..Case::buy()
    });
    assert!(res.is_ok(), "a cheap sale owes nothing and must go through, got {res:?}");
}

/// The control for it: one CKB above the threshold the fee is real again, and leaving it
/// out is refused. Without this, the test above would also pass if the contract had
/// simply stopped charging.
#[test]
fn one_ckb_above_the_threshold_the_fee_is_owed_again() {
    let dear = 6_300 * 100_000_000;
    let fee = cells_core::sale_fee(dear);
    assert_eq!(fee, 63 * 100_000_000, "the fixture has to be at the threshold");
    let short = run(Case { offers: vec![dear], outputs: vec![(W::Seller, dear + OFFER_CAP)], ..Case::buy() });
    assert!(short.is_err(), "the whole price to the seller must not settle a sale that owes a fee");
    let paid = run(Case {
        offers: vec![dear],
        outputs: vec![(W::Seller, dear - fee + OFFER_CAP), (W::Treasury, fee)],
        ..Case::buy()
    });
    assert!(paid.is_ok(), "paying it must go through, got {paid:?}");
}

/// The hole this closed, written as the transaction that exploited it.
///
/// The seller parks OFFER_CAP in the offer cell to publish the listing. Until
/// 2026-09-14 that capacity went to whoever completed the sale, so for any price below
/// it a stranger could spend the offer cell, pay the seller out of the seller's own
/// deposit, and walk away with the name **and** the change. Measured on Pudge that day
/// with a real sale: the buyer brought 0 CKB, the seller "received" 63 and was 97 down.
#[test]
fn a_buyer_cannot_pay_the_seller_with_the_sellers_own_deposit() {
    let cheap = 63 * 100_000_000;
    let res = run(Case {
        offers: vec![cheap],
        // Exactly the shape of the real exploit: the only inputs are the name and the
        // offer cell, and the price comes out of the deposit.
        inputs: vec![],
        outputs: vec![(W::Seller, cheap)],
        ..Case::buy()
    });
    assert!(res.is_err(), "the deposit is not the buyer's to pay with, got {res:?}");
}

/// And the honest version of the same sale: the deposit goes back to the seller on top
/// of the price, so the buyer brings the price and the seller receives the price.
#[test]
fn the_deposit_comes_back_to_the_seller_on_a_sale() {
    let cheap = 63 * 100_000_000;
    let res = run(Case {
        offers: vec![cheap],
        outputs: vec![(W::Seller, cheap + OFFER_CAP)],
        ..Case::buy()
    });
    assert!(res.is_ok(), "price plus the deposit back is a complete sale, got {res:?}");
    // One shannon short of the deposit is not.
    let short = run(Case {
        offers: vec![cheap],
        outputs: vec![(W::Seller, cheap + OFFER_CAP - 1)],
        ..Case::buy()
    });
    assert!(short.is_err(), "keeping any of the deposit must fail");
}
