//! Integration tests for `price-cell-type` (decision 0014; run `make build` first).
//!
//! The script has two jobs: be unforgeable (type-id args on creation) and bound every
//! change (arity, lock, capacity, band, step, cooldown). Each rule has a case that
//! passes with the rule and fails without it. The read side, `account-cell-type`
//! honouring the factor and falling back to the full price, is tested in
//! `account_cell.rs`, because that is the script it belongs to.
use ckb_testtool::builtin::ALWAYS_SUCCESS;
use ckb_testtool::ckb_types::{
    bytes::Bytes,
    core::TransactionBuilder,
    packed::{CellInput, CellOutput, OutPoint},
    prelude::*,
};
use ckb_testtool::context::Context;
use tests::Loader;

use cells_core::{ckb_blake2b256, price_data, PRICE_COOLDOWN_SECS, PRICE_FACTOR_MAX, PRICE_FACTOR_MIN};

const MAX_CYCLES: u64 = 100_000_000;
const CAP: u64 = 500 * 100_000_000;

// Error codes, mirroring the script's `Err` enum.
const BAD_ARGS: u8 = 2;
const ARITY: u8 = 3;
const LOCK_CHANGED: u8 = 4;
const CAPACITY_SHRUNK: u8 = 5;
const BAD_DATA: u8 = 6;
const STEP: u8 = 7;
const COOLDOWN: u8 = 8;

fn rel_ts(secs: u64) -> u64 {
    0xC000_0000_0000_0000 | secs
}
fn abs_ts(t: u64) -> u64 {
    0x4000_0000_0000_0000 | t
}
fn data(bps: u32) -> Bytes {
    Bytes::from(price_data(bps).to_vec())
}
fn assert_code(res: &Result<u64, String>, code: u8, what: &str) {
    let e = res.as_ref().err().unwrap_or_else(|| panic!("{what}: expected a failure, it passed"));
    assert!(e.contains(&format!("error code {code}")), "{what}: wanted error {code}, got {e}");
}
fn price_dir() -> String {
    std::env::var("CELLS_PRICE_DIR")
        .unwrap_or_else(|_| "../target/riscv64imac-unknown-none-elf/release".to_string())
}
fn setup() -> (Context, OutPoint, OutPoint) {
    let mut ctx = Context::default();
    let price_op = ctx.deploy_cell(Loader::at(price_dir()).load_binary("price-cell-type"));
    let plain_op = ctx.deploy_cell(ALWAYS_SUCCESS.clone());
    (ctx, price_op, plain_op)
}

// --- creation ------------------------------------------------------------------

/// Create the price cell: one plain input, and typed output(s). The output args are
/// the type-id of (that input, index 0) unless `args` overrides them.
fn create(out_data: Bytes, args: Option<Bytes>, n_out: usize) -> Result<u64, String> {
    let (mut ctx, price_op, plain_op) = setup();
    let keeper = ctx.build_script(&plain_op, Bytes::from_static(b"keeper")).expect("keeper");
    let in_op = ctx.create_cell(
        CellOutput::new_builder().capacity(CAP.pack()).lock(keeper.clone()).build(),
        Bytes::new(),
    );
    let input = CellInput::new_builder().previous_output(in_op).build();
    // blake2b(first input, then the output index as u64 LE): the type-id construction.
    let type_id = {
        let mut buf = Vec::with_capacity(52);
        buf.extend_from_slice(input.as_slice());
        buf.extend_from_slice(&0u64.to_le_bytes());
        Bytes::from(ckb_blake2b256(&buf).to_vec())
    };
    let s_price = ctx.build_script(&price_op, args.unwrap_or(type_id)).expect("price type");
    let out = CellOutput::new_builder()
        .capacity(CAP.pack())
        .lock(keeper)
        .type_(Some(s_price).pack())
        .build();
    let tx = TransactionBuilder::default()
        .input(input)
        .outputs(vec![out; n_out])
        .outputs_data(vec![out_data.pack(); n_out])
        .build();
    let tx = ctx.complete_tx(tx);
    ctx.verify_tx(&tx, MAX_CYCLES).map_err(|e| format!("{e:?}"))
}

#[test]
fn creation_with_type_id_args_passes() {
    create(data(PRICE_FACTOR_MAX), None, 1).expect("create at the full price");
    // Starting below the ceiling is allowed: the testnet proof starts at 90%.
    create(data(9_000), None, 1).expect("create at a discount");
    create(data(PRICE_FACTOR_MIN), None, 1).expect("create at the floor");
}

#[test]
fn creation_with_any_other_args_is_refused() {
    // A look-alike: the right code with the wrong args. This is the H-1 hole, closed.
    let r = create(data(PRICE_FACTOR_MAX), Some(Bytes::from_static(b"not-a-type-id")), 1);
    assert_code(&r, BAD_ARGS, "forged args");
    let r = create(data(PRICE_FACTOR_MAX), Some(Bytes::from(vec![0u8; 32])), 1);
    assert_code(&r, BAD_ARGS, "zero args");
}

#[test]
fn creation_refuses_bad_data() {
    assert_code(&create(data(PRICE_FACTOR_MIN - 1), None, 1), BAD_DATA, "below the floor");
    assert_code(&create(data(PRICE_FACTOR_MAX + 1), None, 1), BAD_DATA, "above the ceiling");
    let mut v2 = price_data(5_000);
    v2[0] = 2;
    assert_code(&create(Bytes::from(v2.to_vec()), None, 1), BAD_DATA, "unknown version");
    assert_code(&create(Bytes::from(price_data(5_000)[..4].to_vec()), None, 1), BAD_DATA, "short");
    assert_code(&create(Bytes::new(), None, 1), BAD_DATA, "empty");
}

#[test]
fn creation_makes_exactly_one_cell() {
    assert_code(&create(data(PRICE_FACTOR_MAX), None, 2), ARITY, "two price cells at once");
}

// --- update ---------------------------------------------------------------------

struct Upd {
    old: u32,
    new_data: Bytes,
    since: u64,
    same_lock: bool,
    cap_out: u64,
    n_in: usize,
    n_out: usize,
}
impl Upd {
    /// A legitimate nudge: a sixteenth down, six hours old, same lock, same capacity.
    fn good() -> Upd {
        Upd {
            old: PRICE_FACTOR_MAX,
            new_data: data(9_375),
            since: rel_ts(PRICE_COOLDOWN_SECS),
            same_lock: true,
            cap_out: CAP,
            n_in: 1,
            n_out: 1,
        }
    }
}

fn update(u: Upd) -> Result<u64, String> {
    let (mut ctx, price_op, plain_op) = setup();
    let keeper = ctx.build_script(&plain_op, Bytes::from_static(b"keeper")).expect("keeper");
    let thief = ctx.build_script(&plain_op, Bytes::from_static(b"thief")).expect("thief");
    // args are not checked on update (the cell already exists), so any will do.
    let s_price = ctx.build_script(&price_op, Bytes::from_static(b"existing")).expect("price type");
    let mut inputs = Vec::new();
    for _ in 0..u.n_in {
        let op = ctx.create_cell(
            CellOutput::new_builder()
                .capacity(CAP.pack())
                .lock(keeper.clone())
                .type_(Some(s_price.clone()).pack())
                .build(),
            data(u.old),
        );
        inputs.push(CellInput::new_builder().since(u.since.pack()).previous_output(op).build());
    }
    let lock_out = if u.same_lock { keeper } else { thief };
    let out = CellOutput::new_builder()
        .capacity(u.cap_out.pack())
        .lock(lock_out)
        .type_(Some(s_price).pack())
        .build();
    let tx = TransactionBuilder::default()
        .inputs(inputs)
        .outputs(vec![out; u.n_out])
        .outputs_data(vec![u.new_data.pack(); u.n_out])
        .build();
    let tx = ctx.complete_tx(tx);
    ctx.verify_tx(&tx, MAX_CYCLES).map_err(|e| format!("{e:?}"))
}

#[test]
fn a_sixteenth_every_six_hours_passes() {
    update(Upd::good()).expect("a sixteenth down after six hours");
    update(Upd { old: 9_412, new_data: data(PRICE_FACTOR_MAX), ..Upd::good() }).expect("a sixteenth up");
    update(Upd { old: 134, new_data: data(PRICE_FACTOR_MIN), ..Upd::good() }).expect("down to the floor");
    update(Upd { new_data: data(PRICE_FACTOR_MAX), ..Upd::good() }).expect("no change at all");
    // More than six hours is fine; the rule is a minimum age.
    update(Upd { since: rel_ts(PRICE_COOLDOWN_SECS * 120), ..Upd::good() }).expect("a month old");
}

#[test]
fn a_step_over_a_sixteenth_is_refused() {
    assert_code(&update(Upd { new_data: data(9_374), ..Upd::good() }), STEP, "just over a sixteenth down");
    assert_code(&update(Upd { old: 4_000, new_data: data(4_251), ..Upd::good() }), STEP, "just over a sixteenth up");
    assert_code(&update(Upd { old: 4_000, new_data: data(3_749), ..Upd::good() }), STEP, "just over a sixteenth down");
    // The old rule's quarter is refused now, which is the whole change.
    assert_code(&update(Upd { new_data: data(7_500), ..Upd::good() }), STEP, "a quarter, the old limit");
    // Past the ceiling is bad data before it is a step.
    assert_code(&update(Upd { old: 8_000, new_data: data(10_001), ..Upd::good() }), BAD_DATA, "above the ceiling");
}

#[test]
fn too_soon_is_refused() {
    assert_code(&update(Upd { since: rel_ts(PRICE_COOLDOWN_SECS - 1), ..Upd::good() }), COOLDOWN, "a second short of six hours");
    assert_code(&update(Upd { since: 0, ..Upd::good() }), COOLDOWN, "no since at all");
    // An absolute timestamp proves nothing about the age of the cell.
    assert_code(&update(Upd { since: abs_ts(PRICE_COOLDOWN_SECS), ..Upd::good() }), COOLDOWN, "absolute, not relative");
}

#[test]
fn the_lock_and_capacity_are_kept() {
    assert_code(&update(Upd { same_lock: false, ..Upd::good() }), LOCK_CHANGED, "moved to another lock");
    assert_code(&update(Upd { cap_out: CAP - 1, ..Upd::good() }), CAPACITY_SHRUNK, "capacity reduced");
    update(Upd { cap_out: CAP + 100, ..Upd::good() }).expect("capacity may grow");
}

#[test]
fn the_cell_is_never_destroyed_or_duplicated() {
    assert_code(&update(Upd { n_out: 0, ..Upd::good() }), ARITY, "spent without a successor");
    assert_code(&update(Upd { n_out: 2, ..Upd::good() }), ARITY, "split into two");
    assert_code(&update(Upd { n_in: 2, ..Upd::good() }), ARITY, "two merged into one");
}

#[test]
fn an_update_refuses_bad_data() {
    assert_code(&update(Upd { new_data: data(PRICE_FACTOR_MIN - 1), ..Upd::good() }), BAD_DATA, "below the floor");
    assert_code(&update(Upd { new_data: Bytes::new(), ..Upd::good() }), BAD_DATA, "emptied");
}
