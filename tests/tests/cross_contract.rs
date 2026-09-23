//! Two of our contracts in one transaction, which no test had ever done.
//!
//! Every test file here deploys one contract. `account-cell-type` appears in two, `sale-lock`
//! in two, `price-cell-type` in two, and never two of them in the same `Context`. So the
//! question below had never been asked, and it is the question that has already cost this
//! project twice: **F-5** (one sale fee answering two sellers) and **F-2** (two namespaces
//! sharing one treasury) were both the same shape, a total that two independent checks each
//! read as satisfying them.
//!
//! The shape, a third time:
//!
//! * `account-cell-type::require_treasury(need)` sums every **pure output under the
//!   treasury lock** and requires the total to be at least `need`.
//! * `sale-lock` calls `paid_to_pure(&TREASURY_LOCK_HASH)` and requires the total to be at
//!   least the sale's fee.
//!
//! Neither knows the other is running. Both count the same outputs. So a transaction that
//! renews a name and completes a sale, with **one** treasury output large enough for the
//! renewal alone, would satisfy both, and the sale's fee would never be paid.
//!
//! This file builds exactly that transaction and asks the VM.

use ckb_testtool::builtin::ALWAYS_SUCCESS;
use ckb_testtool::ckb_types::{
    bytes::Bytes,
    core::{HeaderBuilder, ScriptHashType, TransactionBuilder},
    packed::*,
    prelude::*,
};
use ckb_testtool::context::Context;
use cells_core::{
    account_id, build_account_data, ckb_blake2b256, sale_fee, NAMESPACE_LEN, OWNER_HASH_LEN, ROOT_ID,
};
use tests::Loader;

const MAX_CYCLES: u64 = 100_000_000;
const CKB: u64 = 100_000_000;
const CAP: u64 = 10_000_000_000;
const HEADER_TS_MS: u64 = 1_700_000_000_000;
const NOW: u64 = HEADER_TS_MS / 1000;
const ONE_YEAR: u64 = 365 * 86_400;
/// One year of a five-plus name, which is what renewing `alice` costs.
const FEE_1Y: u64 = 5_000 * CKB;
const OFFER_CAP: u64 = 100 * CKB;
const SALE_PRICE: u64 = 10_000 * CKB;

/// Renew a name and complete a sale in one transaction, paying the treasury `treasury_out`
/// in a single output. Returns whether both scripts accepted it.
///
/// `treasury_out` is the whole experiment: at `FEE_1Y + sale_fee(SALE_PRICE)` the
/// transaction is honest, and at `FEE_1Y` the renewal's payment is being asked to answer
/// for the sale as well.
fn renew_and_buy(treasury_out: u64) -> Result<u64, String> {
    let mut ctx = Context::default();
    let acct_op = ctx.deploy_cell(Loader::default().load_binary("account-cell-type"));
    let sale_op = ctx.deploy_cell(Loader::default().load_binary("sale-lock"));
    let plain_op = ctx.deploy_cell(ALWAYS_SUCCESS.clone());

    // The namespace: account-cell-type carries the genesis token's hash as its args.
    let token = ctx.build_script(&plain_op, Bytes::from_static(b"genesis-token")).expect("token");
    let acct_type = ctx
        .build_script(&acct_op, token.calc_script_hash().as_bytes().slice(0..NAMESPACE_LEN))
        .expect("acct type");
    let acct_lock = ctx.build_script(&plain_op, Bytes::from_static(b"cells-account-lock")).expect("acct lock");
    let owner_lock = ctx.build_script(&plain_op, Bytes::from_static(b"owner-a")).expect("owner");
    let seller_lock = ctx.build_script(&plain_op, Bytes::from_static(b"seller")).expect("seller");
    let buyer_lock = ctx.build_script(&plain_op, Bytes::from_static(b"buyer")).expect("buyer");
    // Data1 and these args, so the hash matches what the test build was compiled against.
    let treasury_lock = ctx
        .build_script_with_hash_type(&plain_op, ScriptHashType::Data1, Bytes::from_static(b"treasury"))
        .expect("treasury");

    let mut owner_id = [0u8; OWNER_HASH_LEN];
    owner_id.copy_from_slice(&owner_lock.calc_script_hash().as_bytes()[..OWNER_HASH_LEN]);

    // --- the name being renewed ---------------------------------------------------
    let witness_payload = Bytes::from_static(&[0u8; 0]);
    let wh = ckb_blake2b256(&witness_payload);
    let before = build_account_data(&wh, &ROOT_ID, NOW + ONE_YEAR, &owner_id, &owner_id, b"alice");
    let after = build_account_data(&wh, &ROOT_ID, NOW + 2 * ONE_YEAR, &owner_id, &owner_id, b"alice");
    let _ = account_id(b"alice"); // the id is derived, not stored; named here so it is not a mystery

    let name_in = ctx.create_cell(
        CellOutput::new_builder()
            .capacity(CAP.pack())
            .lock(acct_lock.clone())
            .type_(Some(acct_type.clone()).pack())
            .build(),
        Bytes::from(before),
    );

    // --- the name being sold ------------------------------------------------------
    let mut args = seller_lock.calc_script_hash().raw_data().to_vec();
    args.extend_from_slice(&SALE_PRICE.to_le_bytes());
    let sale_lock = ctx.build_script_with_hash_type(&sale_op, ScriptHashType::Data1, Bytes::from(args)).expect("sale lock");
    let offer_in = ctx.create_cell(
        CellOutput::new_builder().capacity(OFFER_CAP.pack()).lock(sale_lock).build(),
        Bytes::from(seller_lock.as_slice().to_vec()),
    );
    // The buyer's own coins, so the sale is paid for by somebody.
    let buyer_in = ctx.create_cell(
        CellOutput::new_builder().capacity((1_000_000 * CKB).pack()).lock(buyer_lock.clone()).build(),
        Bytes::new(),
    );
    // And the owner co-signing the renewal is not needed: renew is permissionless.

    // The header the L-2 expiry check reads.
    let header = HeaderBuilder::default().timestamp(HEADER_TS_MS.pack()).build();
    ctx.insert_header(header.clone());
    ctx.link_cell_with_block(name_in.clone(), header.hash(), 0);

    let fee = sale_fee(SALE_PRICE);
    let outputs = vec![
        // 0: the renewed name
        CellOutput::new_builder()
            .capacity(CAP.pack())
            .lock(acct_lock)
            .type_(Some(acct_type).pack())
            .build(),
        // 1: the seller, paid the price less the fee plus their deposit back
        CellOutput::new_builder()
            .capacity((SALE_PRICE - fee + OFFER_CAP).pack())
            .lock(seller_lock)
            .build(),
        // 2: the treasury, ONE output, and the whole question
        CellOutput::new_builder().capacity(treasury_out.pack()).lock(treasury_lock).build(),
    ];
    let outputs_data = vec![Bytes::from(after), Bytes::new(), Bytes::new()];

    // The action goes in witness 0's input_type, the cell's payload in output_type.
    let action = Bytes::from_static(b"renew");
    let w0 = WitnessArgs::new_builder()
        .input_type(Some(action).pack())
        .output_type(Some(witness_payload).pack())
        .build();
    let witnesses = vec![
        w0.as_bytes().pack(),
        WitnessArgs::new_builder().build().as_bytes().pack(),
        WitnessArgs::new_builder().build().as_bytes().pack(),
    ];

    let tx = TransactionBuilder::default()
        .input(CellInput::new_builder().previous_output(name_in).build())
        .input(CellInput::new_builder().previous_output(offer_in).build())
        .input(CellInput::new_builder().previous_output(buyer_in).build())
        .outputs(outputs)
        .outputs_data(outputs_data.pack())
        .header_dep(header.hash())
        .witnesses(witnesses)
        .build();
    let tx = ctx.complete_tx(tx);
    ctx.verify_tx(&tx, MAX_CYCLES).map_err(|e| format!("{e:?}"))
}

/// The control: paying both fees must work, or the test below proves only that this
/// transaction shape is refused for some unrelated reason.
#[test]
fn renewing_and_buying_together_is_allowed_when_both_fees_are_paid() {
    let both = FEE_1Y + sale_fee(SALE_PRICE);
    let res = renew_and_buy(both);
    assert!(res.is_ok(), "an honest batch of a renewal and a sale must pass, got {res:?}");
}

/// **The question, and the answer is bad.** One treasury output, big enough for the
/// renewal alone, offered to two contracts that both count it and neither of which knows
/// the other is looking.
///
/// **Fixed 2026-09-14**, the same day it was found. `account-cell-type` now adds what the
/// sale locks being spent here already owe the treasury to what it demands itself, so the
/// renewal's payment can no longer answer for the sale as well. One side is enough,
/// because the strictest requirement binds, and this is the side that can do the
/// arithmetic: a sale's fee is `sale_fee(price)` and the price is in the lock's own args.
#[test]
fn one_treasury_output_must_not_answer_a_renewal_and_a_sale_at_once() {
    let res = renew_and_buy(FEE_1Y);
    assert!(
        res.is_err(),
        "the renewal's fee answered the sale's as well: the protocol was paid {} CKB \
         where {} was owed, and the difference is {} CKB taken for nothing. {res:?}",
        FEE_1Y / CKB,
        (FEE_1Y + sale_fee(SALE_PRICE)) / CKB,
        sale_fee(SALE_PRICE) / CKB
    );
}

/// F-2 at last, which had been "untested because the harness cannot build a two-namespace
/// transaction" since it was written.
///
/// It can now: the harness above deploys two contracts in one `Context`, and deploying
/// `account-cell-type` twice with different args is the same trick. Two namespaces are two
/// script hashes, therefore two script groups, therefore two independent runs of
/// `require_treasury` over the same outputs.
///
/// The entry for F-2 says it "is not exploitable today because only one namespace exists".
/// **That mitigation had already stopped being true when it was written**: a second script
/// counting the same treasury outputs does not have to be a second namespace, and
/// `sale-lock` has been one since 2026-09-05. F-9 is F-2, live, and this test is F-2 as
/// originally described.
fn renew_in_two_namespaces(treasury_out: u64) -> Result<u64, String> {
    let mut ctx = Context::default();
    let acct_op = ctx.deploy_cell(Loader::default().load_binary("account-cell-type"));
    let plain_op = ctx.deploy_cell(ALWAYS_SUCCESS.clone());

    let owner_lock = ctx.build_script(&plain_op, Bytes::from_static(b"owner-a")).expect("owner");
    let acct_lock = ctx.build_script(&plain_op, Bytes::from_static(b"cells-account-lock")).expect("acct lock");
    let treasury_lock = ctx
        .build_script_with_hash_type(&plain_op, ScriptHashType::Data1, Bytes::from_static(b"treasury"))
        .expect("treasury");

    // Two namespaces: two genesis tokens, so two different args, so two script groups.
    let token_a = ctx.build_script(&plain_op, Bytes::from_static(b"genesis-token")).expect("token a");
    let token_b = ctx.build_script(&plain_op, Bytes::from_static(b"genesis-token-two")).expect("token b");
    let type_a = ctx
        .build_script(&acct_op, token_a.calc_script_hash().as_bytes().slice(0..NAMESPACE_LEN))
        .expect("type a");
    let type_b = ctx
        .build_script(&acct_op, token_b.calc_script_hash().as_bytes().slice(0..NAMESPACE_LEN))
        .expect("type b");
    assert_ne!(
        type_a.calc_script_hash().as_bytes(),
        type_b.calc_script_hash().as_bytes(),
        "two namespaces must be two script groups or this test is not testing F-2"
    );

    let mut owner_id = [0u8; OWNER_HASH_LEN];
    owner_id.copy_from_slice(&owner_lock.calc_script_hash().as_bytes()[..OWNER_HASH_LEN]);
    let witness_payload = Bytes::from_static(&[0u8; 0]);
    let wh = ckb_blake2b256(&witness_payload);

    let mut inputs = Vec::new();
    let mut outputs = Vec::new();
    let mut outputs_data = Vec::new();
    let header = HeaderBuilder::default().timestamp(HEADER_TS_MS.pack()).build();
    ctx.insert_header(header.clone());

    for (label, ty) in [(&b"alice"[..], &type_a), (&b"bobby"[..], &type_b)] {
        let before = build_account_data(&wh, &ROOT_ID, NOW + ONE_YEAR, &owner_id, &owner_id, label);
        let after = build_account_data(&wh, &ROOT_ID, NOW + 2 * ONE_YEAR, &owner_id, &owner_id, label);
        let op = ctx.create_cell(
            CellOutput::new_builder()
                .capacity(CAP.pack())
                .lock(acct_lock.clone())
                .type_(Some((*ty).clone()).pack())
                .build(),
            Bytes::from(before),
        );
        ctx.link_cell_with_block(op.clone(), header.hash(), 0);
        inputs.push(CellInput::new_builder().previous_output(op).build());
        outputs.push(
            CellOutput::new_builder()
                .capacity(CAP.pack())
                .lock(acct_lock.clone())
                .type_(Some((*ty).clone()).pack())
                .build(),
        );
        outputs_data.push(Bytes::from(after));
    }
    // One treasury output for two renewals.
    outputs.push(CellOutput::new_builder().capacity(treasury_out.pack()).lock(treasury_lock).build());
    outputs_data.push(Bytes::new());

    // Each namespace's group reads the witness at ITS first output's index, so both
    // outputs carry the action and the payload.
    let action = Bytes::from_static(b"renew");
    let w = |_i: usize| {
        WitnessArgs::new_builder()
            .input_type(Some(action.clone()).pack())
            .output_type(Some(witness_payload.clone()).pack())
            .build()
            .as_bytes()
            .pack()
    };
    let witnesses = vec![w(0), w(1), WitnessArgs::new_builder().build().as_bytes().pack()];

    let tx = TransactionBuilder::default()
        .inputs(inputs)
        .outputs(outputs)
        .outputs_data(outputs_data.pack())
        .header_dep(header.hash())
        .witnesses(witnesses)
        .build();
    let tx = ctx.complete_tx(tx);
    ctx.verify_tx(&tx, MAX_CYCLES).map_err(|e| format!("{e:?}"))
}

/// The control: two namespaces renewing, paying both fees, must pass.
#[test]
fn two_namespaces_renewing_together_is_allowed_when_both_fees_are_paid() {
    let res = renew_in_two_namespaces(2 * FEE_1Y);
    assert!(res.is_ok(), "two honest renewals in two namespaces must pass, got {res:?}");
}

/// F-2 itself: one fee, two namespaces.
#[test]
fn one_fee_must_not_answer_two_namespaces() {
    let res = renew_in_two_namespaces(FEE_1Y);
    assert!(
        res.is_err(),
        "one fee of {} CKB answered two renewals owing {} CKB between them. {res:?}",
        FEE_1Y / CKB,
        2 * FEE_1Y / CKB
    );
}
