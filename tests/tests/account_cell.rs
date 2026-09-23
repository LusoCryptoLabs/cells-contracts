//! Integration tests for `account-cell-type` (run `make build` first).
//!
//! Phase 2 (decision 0002): the AccountCell lock is a uniform always-success, so
//! the type script is the sole guardian. These tests exercise:
//!   * output integrity (id ↔ label, witness_hash);
//!   * **permissionless** `register`, no sequencer, with full predecessor
//!     preservation (tampering the predecessor's owner / capacity / witness is
//!     rejected);
//!   * **owner-gated** `edit` / `transfer`, the tx must co-spend a cell under the
//!     account's `owner_lock_hash`;
//!   * permissionless `renew` / `recycle`, and the sequencer-gated genesis.
use ckb_testtool::builtin::ALWAYS_SUCCESS;
use ckb_testtool::ckb_types::{
    bytes::Bytes,
    core::{HeaderBuilder, ScriptHashType, TransactionBuilder},
    packed::{Byte32, BytesOpt, CellDep, CellInput, CellOutput, Script, WitnessArgs},
    prelude::*,
};
use ckb_testtool::context::Context;
use tests::Loader;

use cells_core::{
    account_id, ckb_blake2b256, commitment, RecordEntry, WitnessData, COMMIT_MIN_DELAY,
    DATA_HEADER_LEN, EXPIRY_LEN, NAMESPACE_LEN, OFF_ACCOUNT, OFF_EXPIRED_AT, OFF_MANAGER,
    OFF_NEXT, OFF_OWNER, OFF_VERSION, OFF_WITNESS_HASH, OWNER_HASH_LEN, ROOT_ID, SECRET_LEN,
    VERSION_V3, Id, between, covers,
};

const MAX_CYCLES: u64 = 100_000_000;
const CAP: u64 = 10_000_000_000;
/// The harness "now", the CommitCell's block timestamp (ms), ~2023.
const HEADER_TS_MS: u64 = 1_700_000_000_000;
/// The same instant in seconds, as the contract reads it from that header.
const NOW: u64 = HEADER_TS_MS / 1000;
const ONE_YEAR: u64 = 365 * 86_400;
/// A year from "now": the shortest term `register` accepts (decision 0009). This
/// used to be the year 2096, which the term rule now rejects as over ten years.
const FUTURE: u64 = NOW + ONE_YEAR;
/// One year of a five-plus-character name, the fee every fixture here pays.
const FEE_1Y: u64 = 5_000 * 100_000_000;

/// Assert the script failed **for the reason under test**, not merely that it failed.
/// `register_rejects_underpriced` passed for a long time while omitting the commit,
/// so what it actually proved was that a missing commit is rejected.
fn assert_code(res: &Result<u64, String>, code: u8, what: &str) {
    let e = res.as_ref().err().unwrap_or_else(|| panic!("{what}: expected a failure, it passed"));
    assert!(e.contains(&format!("error code {code}")), "{what}: wanted error {code}, got {e}");
}

/// Lock selector. `Acct` is the uniform AccountCell lock; `A`/`B` are owner
/// wallets (their hashes go in `owner_lock_hash` and are used to co-sign owner
/// actions); `Seq` is the genesis sequencer. Each maps to always-success with
/// distinct args → a distinct script hash.
#[derive(Clone, Copy)]
enum L {
    Acct,
    A,
    B,
    Seq,
    /// The treasury the registration fee must be paid to (decision 0009). Its args
    /// must match `TREASURY_ARGS` in src/bin/treasury-hash.rs, which is what tells
    /// the test build of the contract which hash to expect.
    Treasury,
    /// An all-zero owner_lock_hash, used only to test the L-1 null-owner guard.
    Null,
}
fn lock_args(l: L) -> Bytes {
    match l {
        L::Acct => Bytes::from_static(b"cells-account-lock"),
        L::A => Bytes::from_static(b"owner-a"),
        L::B => Bytes::from_static(b"owner-b"),
        L::Seq => Bytes::from_static(b"sequencer"),
        L::Treasury => Bytes::from_static(b"treasury"),
        L::Null => Bytes::from_static(b"null"), // never built as a real lock
    }
}

/// An input AccountCell. `lock` is the cell's own lock (normally `Acct`); `owner`
/// selects whose hash is written into `data.owner_lock_hash`.
struct InC {
    data: Bytes,
    lock: L,
    owner: L,
    /// `None` is "the owner": an undelegated cell carries its owner in both fields.
    manager: Option<L>,
    since: u64,
}
/// An output AccountCell. `cap` lets a test shrink the predecessor capacity.
/// `plain` makes it an ordinary cell instead: no type script and no data, which is
/// what the treasury payment is. The type script collects its group by type hash, so
/// a plain output is invisible to the register/renew arity checks.
struct OutC {
    data: Bytes,
    witness: Bytes,
    lock: L,
    owner: L,
    /// `None` is "the owner", the undelegated case; `Some` sets a delegate.
    manager: Option<L>,
    cap: u64,
    plain: bool,
    /// A plain output that nevertheless carries a (foreign) type script: what a
    /// payment looks like when the payer attaches a hostile type to it.
    typed: bool,
}

fn inc(data: &Bytes) -> InC {
    InC { data: data.clone(), lock: L::Acct, owner: L::A, manager: None, since: 0 }
}
fn outc(data: &Bytes, witness: &Bytes) -> OutC {
    OutC {
        data: data.clone(),
        witness: witness.clone(),
        lock: L::Acct,
        owner: L::A,
        manager: None,
        cap: CAP,
        plain: false,
        typed: false,
    }
}

/// The registration fee, paid to the treasury lock (decision 0009). Always appended
/// last, so the account cells keep indices 0 and 1 and the reveal secret stays in
/// the witness the contract reads.
fn treasury_out(cap: u64) -> OutC {
    plain_out(L::Treasury, cap)
}

/// An ordinary output paying some lock: the treasury's fee, or an inviter's cut.
fn plain_out(lock: L, cap: u64) -> OutC {
    OutC {
        data: Bytes::new(),
        witness: Bytes::new(),
        lock,
        owner: L::A,
        manager: None,
        cap,
        plain: true,
        typed: false,
    }
}

/// Build an AccountCell's `data` (correct witness_hash; owner left zeroed, `verify`
/// patches `owner_lock_hash` from the cell's `owner` selector) + its payload.
fn account_cell(
    // Kept in the signature so the fixtures read as they always did; the cell does
    // not store an id any more (decision 0015), the label determines it.
    _id: cells_core::Id,
    next: cells_core::Id,
    expired_at: u64,
    label: &[u8],
    witness: &WitnessData,
) -> (Bytes, Bytes) {
    let payload = witness.encode();
    let wh = ckb_blake2b256(&payload);
    let mut d = vec![0u8; DATA_HEADER_LEN];
    d[OFF_VERSION] = VERSION_V3;
    d[OFF_WITNESS_HASH..OFF_NEXT].copy_from_slice(&wh);
    d[OFF_NEXT..OFF_EXPIRED_AT].copy_from_slice(&next);
    d[OFF_EXPIRED_AT..OFF_OWNER].copy_from_slice(&expired_at.to_le_bytes()[..EXPIRY_LEN]);
    // owner and manager stay zero here; patched in `verify`.
    d.extend_from_slice(label);
    (Bytes::from(d), Bytes::from(payload))
}

/// There is one layout now and a delegated cell is the same cell with a different
/// manager. Kept so the tests about delegation keep reading naturally.
fn account_cell_v2(
    id: cells_core::Id,
    next: cells_core::Id,
    expired_at: u64,
    label: &[u8],
    witness: &WitnessData,
) -> (Bytes, Bytes) {
    account_cell(id, next, expired_at, label, witness)
}

fn bytes_opt(b: &Bytes) -> BytesOpt {
    BytesOpt::new_builder().set(Some(b.clone().pack())).build()
}
fn abs_ts(t: u64) -> u64 {
    0x4000_0000_0000_0000 | t // absolute-timestamp `since`
}
fn rel_ts(secs: u64) -> u64 {
    0xC000_0000_0000_0000 | secs // relative-timestamp `since` (commit-reveal MIN_DELAY)
}

/// A CommitCell to attach to a `register` tx (commit-reveal). `verify` computes the
/// correct `blake2b(namespace ‖ label ‖ owner ‖ secret)` from the new cell (output
/// 1) unless `bad_data` overrides it, injects `secret` into the new cell's witness,
/// and gives the commit input the given `since`.
struct Commit {
    secret: [u8; SECRET_LEN],
    since: u64,
    bad_data: Option<Bytes>,
    /// Who HOLDS the commit cell. It must be the owner the commitment names; the
    /// fixture used to hardcode `L::A` while every register fixture also owned as
    /// `L::A`, so holder and owner were never varied independently and the
    /// front-running hole was invisible to the whole suite.
    holder: L,
}
impl Commit {
    /// A well-formed, sufficiently-old commit (the happy path).
    fn good() -> Commit {
        Commit {
            secret: [0x77; SECRET_LEN],
            since: rel_ts(COMMIT_MIN_DELAY),
            bad_data: None,
            holder: L::A,
        }
    }
}

/// Assemble and verify a tx. `extra_inputs` adds plain (type-less) inputs under
/// the given locks, used for owner co-signs (`A`/`B`). `with_token` adds the
/// one-time genesis-token input (needed only by genesis). The token's type hash is
/// the namespace id = `account-cell-type`'s args, so genesis must consume it.
/// 5-arg wrapper for the non-register actions (no commit-reveal).
fn verify(
    ins: &[InC],
    outs: &[OutC],
    action: &[u8],
    extra_inputs: &[L],
    with_token: bool,
) -> Result<u64, String> {
    verify_full(ins, outs, action, extra_inputs, with_token, None)
}

fn verify_full(
    ins: &[InC],
    outs: &[OutC],
    action: &[u8],
    extra_inputs: &[L],
    with_token: bool,
    commit: Option<&Commit>,
) -> Result<u64, String> {
    verify_sub(ins, outs, action, extra_inputs, with_token, commit, None)
}

/// As `verify_full`, plus an optional **parent AccountCell supplied as a cell dep**
/// how a sub-name proves its parent exists and authorizes it (decision 0008).
fn verify_sub(
    ins: &[InC],
    outs: &[OutC],
    action: &[u8],
    extra_inputs: &[L],
    with_token: bool,
    commit: Option<&Commit>,
    parent: Option<(&Bytes, L)>,
) -> Result<u64, String> {
    verify_priced(ins, outs, action, extra_inputs, with_token, commit, parent, None)
}

/// As `verify_sub`, plus an optional **price cell supplied as a cell dep** (decision
/// 0014): its data, which `account-cell-type` reads for the discount factor. It is
/// Data1-hashed with fixed args so it hashes to the `CELLS_PRICE_CELL_TYPE_HASH` the
/// test build was compiled with (src/bin/price-hash.rs). A dep's type script does not
/// run, so malformed data is a valid thing to present here, and it is tested.
#[allow(clippy::too_many_arguments)]
fn verify_priced(
    ins: &[InC],
    outs: &[OutC],
    action: &[u8],
    extra_inputs: &[L],
    with_token: bool,
    commit: Option<&Commit>,
    parent: Option<(&Bytes, L)>,
    price: Option<&Bytes>,
) -> Result<u64, String> {
    let mut ctx = Context::default();
    let acct_op = ctx.deploy_cell(Loader::default().load_binary("account-cell-type"));
    let lock_op = ctx.deploy_cell(ALWAYS_SUCCESS.clone());

    // The genesis-token type script (stands in for a type-id cell in tests); its
    // hash is the namespace id that account-cell-type carries as its args.
    let s_token = ctx.build_script(&lock_op, Bytes::from_static(b"genesis-token")).expect("token");
    let acct_type = ctx
        .build_script(&acct_op, s_token.calc_script_hash().as_bytes().slice(0..NAMESPACE_LEN))
        .expect("acct type");
    // Precompute every lock script up front (build_script needs &mut ctx), so the
    // helper closures below are pure and leave ctx free for create_cell/complete_tx.
    let s_acct = ctx.build_script(&lock_op, lock_args(L::Acct)).expect("acct lock");
    let s_a = ctx.build_script(&lock_op, lock_args(L::A)).expect("a");
    let s_b = ctx.build_script(&lock_op, lock_args(L::B)).expect("b");
    let s_seq = ctx.build_script(&lock_op, lock_args(L::Seq)).expect("seq");
    // Data1, so the treasury lock hashes the same on every run and can be compiled
    // into the contract. `build_script` would use the deployed cell's type-id hash,
    // whose args ckb-testtool randomises per Context. See src/bin/treasury-hash.rs.
    let s_treasury = ctx
        .build_script_with_hash_type(&lock_op, ScriptHashType::Data1, lock_args(L::Treasury))
        .expect("treasury");
    // A foreign type script a payer can attach to a payment output. Always-success
    // here, so the only thing it can trip is the guardian's own rule about it.
    let s_hostile = ctx.build_script(&lock_op, Bytes::from_static(b"hostile-type")).expect("hostile");
    let pick = |l: L| -> Script {
        match l {
            L::Acct => s_acct.clone(),
            L::A => s_a.clone(),
            L::B => s_b.clone(),
            L::Seq => s_seq.clone(),
            L::Treasury => s_treasury.clone(),
            L::Null => s_acct.clone(), // unused as a real lock (Null is owner-only)
        }
    };
    let owner_hash = |l: L| -> [u8; OWNER_HASH_LEN] {
        if let L::Null = l {
            return [0u8; OWNER_HASH_LEN]; // the all-zero owner the L-1 guard rejects
        }
        let mut h = [0u8; OWNER_HASH_LEN];
        h.copy_from_slice(&pick(l).calc_script_hash().as_bytes()[..OWNER_HASH_LEN]);
        h
    };
    // Patch the owner and manager identities into a cell's data. Both fields are
    // always present; an undelegated cell simply carries the owner twice.
    let with_ident = |data: &Bytes, owner: L, manager: L| -> Bytes {
        let mut d = data.to_vec();
        d[OFF_OWNER..OFF_MANAGER].copy_from_slice(&owner_hash(owner));
        d[OFF_MANAGER..OFF_ACCOUNT].copy_from_slice(&owner_hash(manager));
        Bytes::from(d)
    };

    let mut inputs: Vec<CellInput> = ins
        .iter()
        .map(|c| {
            let op = ctx.create_cell(
                CellOutput::new_builder()
                    .capacity(CAP.pack())
                    .lock(pick(c.lock))
                    .type_(Some(acct_type.clone()).pack())
                    .build(),
                with_ident(&c.data, c.owner, c.manager.unwrap_or(c.owner)),
            );
            CellInput::new_builder().since(c.since.pack()).previous_output(op).build()
        })
        .collect();

    for &l in extra_inputs {
        let op = ctx.create_cell(
            CellOutput::new_builder().capacity(CAP.pack()).lock(pick(l)).build(),
            Bytes::new(),
        );
        inputs.push(CellInput::new_builder().previous_output(op).build());
    }

    // The CommitCell (commit-reveal): a plain cell whose whole data is the
    // commitment for the new name (output 1), spent with a relative-timestamp since.
    // It is linked to a block (HEADER_TS_MS) so the contract can read "now" from its
    // header for the L-2 future-expiry check.
    let mut header_deps: Vec<Byte32> = Vec::new();
    if let Some(cm) = commit {
        let mut ns = [0u8; NAMESPACE_LEN];
        ns.copy_from_slice(&s_token.calc_script_hash().as_bytes()[..NAMESPACE_LEN]);
        let x = &outs[1];
        let data = cm.bad_data.clone().unwrap_or_else(|| {
            let label = &x.data[OFF_ACCOUNT..];
            Bytes::from(commitment(&ns, label, &owner_hash(x.owner), &cm.secret).to_vec())
        });
        let op = ctx.create_cell(
            CellOutput::new_builder().capacity(CAP.pack()).lock(pick(cm.holder)).build(),
            data,
        );
        let header = HeaderBuilder::default().timestamp(HEADER_TS_MS.pack()).build();
        ctx.insert_header(header.clone());
        ctx.link_cell_with_block(op.clone(), header.hash(), 0);
        header_deps.push(header.hash());
        inputs.push(CellInput::new_builder().since(cm.since.pack()).previous_output(op).build());
    }

    // The one-time genesis-token input (its type hash == the namespace id).
    if with_token {
        let op = ctx.create_cell(
            CellOutput::new_builder()
                .capacity(CAP.pack())
                .lock(pick(L::A))
                .type_(Some(s_token.clone()).pack())
                .build(),
            Bytes::new(),
        );
        inputs.push(CellInput::new_builder().previous_output(op).build());
    }

    let out_cells: Vec<CellOutput> = outs
        .iter()
        .map(|c| {
            let b = CellOutput::new_builder().capacity(c.cap.pack()).lock(pick(c.lock));
            if c.plain && c.typed {
                b.type_(Some(s_hostile.clone()).pack()).build()
            } else if c.plain {
                b.build()
            } else {
                b.type_(Some(acct_type.clone()).pack()).build()
            }
        })
        .collect();
    let outputs_data: Vec<_> = outs
        .iter()
        .map(|c| {
            if c.plain { Bytes::new().pack() } else { with_ident(&c.data, c.owner, c.manager.unwrap_or(c.owner)).pack() }
        })
        .collect();

    let action_b = Bytes::from(action.to_vec());
    let witnesses: Vec<_> = outs
        .iter()
        .enumerate()
        .map(|(i, c)| {
            let mut wb = WitnessArgs::new_builder().output_type(bytes_opt(&c.witness));
            if i == 0 {
                wb = wb.input_type(bytes_opt(&action_b));
            } else if i == 1 {
                // The new cell's witness carries the reveal secret in `input_type`.
                if let Some(cm) = commit {
                    wb = wb.input_type(bytes_opt(&Bytes::from(cm.secret.to_vec())));
                }
            }
            wb.build().as_bytes().pack()
        })
        .collect();

    let mut tb = TransactionBuilder::default()
        .inputs(inputs)
        .outputs(out_cells)
        .outputs_data(outputs_data)
        .cell_dep(CellDep::new_builder().out_point(acct_op).build())
        .header_deps(header_deps)
        .witnesses(witnesses);

    // The parent AccountCell, read-only as a cell dep: a dep must be a live cell, so
    // this is what proves the parent exists without disturbing it.
    if let Some((pdata, powner)) = parent {
        let op = ctx.create_cell(
            CellOutput::new_builder()
                .capacity(CAP.pack())
                .lock(pick(powner))
                .type_(Some(acct_type.clone()).pack())
                .build(),
            with_ident(pdata, powner, powner),
        );
        tb = tb.cell_dep(CellDep::new_builder().out_point(op).build());
    }
    if let Some(pdata) = price {
        let price_dir = std::env::var("CELLS_PRICE_DIR")
            .unwrap_or_else(|_| "../target/riscv64imac-unknown-none-elf/release".to_string());
        let price_op = ctx.deploy_cell(Loader::at(price_dir).load_binary("price-cell-type"));
        let s_price = ctx
            .build_script_with_hash_type(&price_op, ScriptHashType::Data1, Bytes::from_static(b"price"))
            .expect("price type");
        let op = ctx.create_cell(
            CellOutput::new_builder()
                .capacity(CAP.pack())
                .lock(pick(L::A))
                .type_(Some(s_price).pack())
                .build(),
            pdata.clone(),
        );
        tb = tb.cell_dep(CellDep::new_builder().out_point(op).build());
    }
    let tx = ctx.complete_tx(tb.build());
    ctx.verify_tx(&tx, MAX_CYCLES).map_err(|e| format!("{e:?}"))
}

fn records_witness() -> WitnessData {
    WitnessData { records: vec![] }
}

// --- genesis ---------------------------------------------------------------

#[test]
fn genesis_creates_root() {
    let (root_d, root_w) = account_cell(ROOT_ID, ROOT_ID, 0, b"", &WitnessData::default());
    // with_token=true consumes the one-time genesis-token. The root is ownerless: the
    // harness default of owner A was minting a root somebody could edit (pass 7, P7-1).
    let res = verify(&[], &[OutC { owner: L::Null, ..outc(&root_d, &root_w) }], b"", &[], true);
    assert!(res.is_ok(), "genesis should pass, got {res:?}");
}

#[test]
fn genesis_rejects_non_root() {
    let id = account_id(b"alice");
    let (d, w) = account_cell(id, ROOT_ID, FUTURE, b"alice", &records_witness());
    let res = verify(&[], &[outc(&d, &w)], b"", &[], true);
    assert!(res.is_err(), "genesis must only create the root sentinel");
}

#[test]
fn genesis_rejects_without_token() {
    // The one-time genesis-token is not consumed → must reject (no forged root).
    let (root_d, root_w) = account_cell(ROOT_ID, ROOT_ID, 0, b"", &WitnessData::default());
    let res = verify(&[], &[outc(&root_d, &root_w)], b"", &[], false);
    assert!(res.is_err(), "genesis must consume the one-time genesis-token");
}

// --- register (permissionless) ---------------------------------------------

/// `price_floor`, now flat, so this is what every name locks whatever its length.
const ALICE_PRICE: u64 = 240 * 100_000_000;

fn register_fixture() -> (InC, Vec<OutC>) {
    let alice = account_id(b"alice");
    let root_w = WitnessData::default();
    let (root_before, _) = account_cell(ROOT_ID, ROOT_ID, 0, b"", &root_w);
    let (root_after, root_after_w) = account_cell(ROOT_ID, alice, 0, b"", &root_w);
    let (alice_d, alice_w) = account_cell(alice, ROOT_ID, FUTURE, b"alice", &records_witness());
    (
        inc(&root_before),
        vec![
            outc(&root_after, &root_after_w),
            OutC { cap: ALICE_PRICE, ..outc(&alice_d, &alice_w) }, // meet the price floor
            treasury_out(FEE_1Y), // and pay the fee, which is not refundable
        ],
    )
}

/// White-hat check: `require_treasury` and `paid_to` counted any output by lock and
/// capacity, the exact shape `sale-lock` was fixed for on 2026-09-05 ("a hostile type
/// script on the payout"). A fee output carrying a type the treasury does not control
/// (an always-fail, or a joint-custody type) meets the capacity while the funds are
/// not the treasury's to spend. The payer gains nothing, it is a burn or a ransom
/// lever on protocol revenue, so a payment must be a pure cell, as a sale already is.
#[test]
fn register_rejects_a_typed_fee_output() {
    let (i, mut o) = register_fixture();
    o[2].typed = true; // the treasury output, with a foreign type script attached
    let res = verify_full(&[i], &o, b"register", &[], false, Some(&Commit::good()));
    assert_code(&res, 42, "a fee paid into a typed cell is not a payment to the treasury");
}

#[test]
fn register_is_permissionless() {
    let (i, o) = register_fixture();
    // No sequencer, no owner co-sign, no ConfigCell, anyone may register, but a
    // valid (matured) commit-reveal is required (anti front-running, decision 0004).
    let res = verify_full(&[i], &o, b"register", &[], false, Some(&Commit::good()));
    assert!(res.is_ok(), "permissionless register with a valid commit should pass, got {res:?}");
}

// --- referrals (decision 0011) ---------------------------------------------

/// A tenth of one year of a five-plus name, and what the treasury is left with.
const CUT_1Y: u64 = FEE_1Y / 10;
const TREASURY_AFTER_CUT: u64 = FEE_1Y - CUT_1Y;

/// A live name to name as the inviter, supplied to `verify_sub` as a cell dep. The
/// contract does not care that it is not `alice`'s parent: any AccountCell of this
/// namespace in the deps is a candidate, and only the payment and the disqualifiers
/// decide.
fn inviter_cell() -> Bytes {
    let (d, _) = account_cell(account_id(b"telmo"), ROOT_ID, FUTURE, b"telmo", &records_witness());
    d
}

/// `register_fixture`, with the treasury paid a tenth less and `to` paid the tenth.
fn referral_fixture(treasury: u64, to: L, cut: u64) -> (InC, Vec<OutC>) {
    let (i, mut o) = register_fixture();
    o.pop(); // the full-fee treasury output
    o.push(treasury_out(treasury));
    o.push(plain_out(to, cut));
    (i, o)
}

#[test]
fn referral_pays_the_inviter_out_of_the_treasury_share() {
    let (i, o) = referral_fixture(TREASURY_AFTER_CUT, L::B, CUT_1Y);
    let res = verify_sub(
        &[i],
        &o,
        b"register",
        &[],
        false,
        Some(&Commit::good()),
        Some((&inviter_cell(), L::B)),
    );
    assert!(res.is_ok(), "a paid inviter should buy its cut off the treasury, got {res:?}");
}

#[test]
fn referral_without_an_inviter_still_owes_the_whole_fee() {
    // The control for every test below: the same short treasury payment, and the
    // tenth paid to B, but no inviter dep at all. Paying somebody is not a referral.
    let (i, o) = referral_fixture(TREASURY_AFTER_CUT, L::B, CUT_1Y);
    let res = verify_full(&[i], &o, b"register", &[], false, Some(&Commit::good()));
    assert_code(&res, 42, "a referral needs a real name as its inviter");
}

#[test]
fn referral_needs_the_inviter_paid_in_full() {
    let (i, o) = referral_fixture(TREASURY_AFTER_CUT, L::B, CUT_1Y - 1);
    let res = verify_sub(
        &[i],
        &o,
        b"register",
        &[],
        false,
        Some(&Commit::good()),
        Some((&inviter_cell(), L::B)),
    );
    assert_code(&res, 42, "an inviter paid a shannon short earns nothing");
}

#[test]
fn referral_discount_is_exactly_a_tenth() {
    // Pay the inviter its cut, then keep one shannon more of the treasury's share.
    let (i, o) = referral_fixture(TREASURY_AFTER_CUT - 1, L::B, CUT_1Y);
    let res = verify_sub(
        &[i],
        &o,
        b"register",
        &[],
        false,
        Some(&Commit::good()),
        Some((&inviter_cell(), L::B)),
    );
    assert_code(&res, 42, "the discount is the cut and not a shannon more");
}

#[test]
fn referral_is_denied_to_anyone_who_signed() {
    // B owns the inviting name AND spends a cell here, so B is the buyer's own
    // wallet as far as the chain can tell. This is the rule that stops a client
    // quietly paying the cut to itself.
    //
    // It stops only the lazy version of that. The commit forces the new OWNER to
    // sign, but nothing forces the inviter to, so one person holding a second wallet
    // still earns the discount and the chain cannot tell. See F-1 in SECURITY.md:
    // the guard is a speed bump, and the test below that passes with an unsigned
    // inviter is that same transaction seen from the other side.
    let (i, o) = referral_fixture(TREASURY_AFTER_CUT, L::B, CUT_1Y);
    let res = verify_sub(
        &[i],
        &o,
        b"register",
        &[L::B],
        false,
        Some(&Commit::good()),
        Some((&inviter_cell(), L::B)),
    );
    assert_code(&res, 42, "an inviter who signed the transaction earns nothing");
}

#[test]
fn referral_is_denied_to_the_treasury() {
    // Without this the treasury's own fee output would be counted twice, once as
    // the fee and once as the cut, and every registration would be a tenth cheaper.
    let (i, mut o) = register_fixture();
    o.pop();
    o.push(treasury_out(TREASURY_AFTER_CUT));
    let res = verify_sub(
        &[i],
        &o,
        b"register",
        &[],
        false,
        Some(&Commit::good()),
        Some((&inviter_cell(), L::Treasury)),
    );
    assert_code(&res, 42, "the treasury may not invite itself out of its own fee");
}

// --- sub-names (decision 0008) ---------------------------------------------

/// Register `shop.telmo` under a parent `telmo` owned by `owner`, with the parent
/// supplied as a cell dep. `child_expiry` lets a test push the child past the parent.
fn subname_fixture(child_expiry: u64) -> (InC, Vec<OutC>, Bytes) {
    let sub = account_id(b"shop.telmo");
    let root_w = WitnessData::default();
    let (root_before, _) = account_cell(ROOT_ID, ROOT_ID, 0, b"", &root_w);
    let (root_after, root_after_w) = account_cell(ROOT_ID, sub, 0, b"", &root_w);
    let (sub_d, sub_w) = account_cell(sub, ROOT_ID, child_expiry, b"shop.telmo", &records_witness());
    // the parent name, as it lives on chain
    let (parent_d, _) = account_cell(account_id(b"telmo"), ROOT_ID, FUTURE, b"telmo", &records_witness());
    (
        inc(&root_before),
        vec![
            outc(&root_after, &root_after_w),
            OutC { cap: ALICE_PRICE, ..outc(&sub_d, &sub_w) },
            treasury_out(FEE_1Y), // "shop.telmo" is a five-plus name like any other
        ],
        parent_d,
    )
}

#[test]
fn subname_registers_with_the_parent_owner() {
    let (i, o, parent) = subname_fixture(FUTURE);
    // parent supplied as a dep AND a cell under the parent owner's lock is spent
    let res = verify_sub(&[i], &o, b"register", &[L::B], false, Some(&Commit::good()), Some((&parent, L::B)));
    assert!(res.is_ok(), "the parent's owner may create a sub-name, got {res:?}");
}

#[test]
fn subname_rejects_without_the_parent() {
    let (i, o, _) = subname_fixture(FUTURE);
    // No parent dep at all: this is the squatting case the rule exists to stop.
    assert!(
        verify_sub(&[i], &o, b"register", &[L::B], false, Some(&Commit::good()), None).is_err(),
        "a sub-name must present its parent"
    );
}

#[test]
fn subname_rejects_a_stranger() {
    let (i, o, parent) = subname_fixture(FUTURE);
    // The parent is present and live, but the tx is co-signed by someone else, so
    // simply knowing a parent exists is not enough to mint under it.
    assert!(
        verify_sub(&[i], &o, b"register", &[L::A], false, Some(&Commit::good()), Some((&parent, L::B))).is_err(),
        "only the parent's owner may create a sub-name"
    );
}

#[test]
fn subname_cannot_outlive_its_parent() {
    // The parent expires at FUTURE; the child asks for one second more.
    let (i, o, parent) = subname_fixture(FUTURE + 1);
    assert!(
        verify_sub(&[i], &o, b"register", &[L::B], false, Some(&Commit::good()), Some((&parent, L::B))).is_err(),
        "a sub-name must not outlive the parent that authorized it"
    );
}

/// Renew `shop.telmo` (child owned by A, parent `telmo` owned by B) by one year, the
/// parent supplied as a cell dep, with cells under `signers` spent alongside.
fn subname_renew(signers: &[L]) -> Result<u64, String> {
    let sub = account_id(b"shop.telmo");
    let w = records_witness();
    let (din, _) = account_cell(sub, ROOT_ID, FUTURE - ONE_YEAR, b"shop.telmo", &w);
    let (dout, pout) = account_cell(sub, ROOT_ID, FUTURE, b"shop.telmo", &w);
    let (parent_d, _) = account_cell(account_id(b"telmo"), ROOT_ID, FUTURE, b"telmo", &records_witness());
    // A child pays a fifth of its parent's band (decision 0023).
    let outs = [outc(&dout, &pout), treasury_out(FEE_1Y / 5)];
    verify_sub(&[inc(&din)], &outs, b"renew", signers, false, None, Some((&parent_d, L::B)))
}

/// A sub-name lives at the pleasure of whoever holds its parent, at creation AND at
/// every renewal. Renewal used to be permissionless like a plain name's, so the holder
/// of `shop.brand` could renew `brand` for its owner (anyone may) and then `shop.brand`
/// for themselves, and keep the child alive through a change of the parent's hands,
/// including a recycle and a fresh registration by a stranger (SECURITY.md pass 6
/// design note, and the rule he set on 2026-09-17: if the parent is not renewed by
/// the same wallet, the child expires).
#[test]
fn subname_renew_by_nobody_is_refused() {
    assert_code(&subname_renew(&[]), 29, "renewing a sub-name with nobody's signature");
}

#[test]
fn subname_renew_by_the_child_owner_alone_is_refused() {
    // A owns the child and signs; B owns the parent and does not. The child's life is
    // B's to extend, not A's.
    assert_code(&subname_renew(&[L::A]), 29, "renewing a sub-name without the parent's owner");
}

#[test]
fn subname_renew_by_the_parent_owner_passes() {
    let res = subname_renew(&[L::B]);
    assert!(res.is_ok(), "the parent's owner may renew a sub-name, got {res:?}");
}

#[test]
fn register_rejects_without_commit() {
    let (i, o) = register_fixture();
    // Everything valid but no CommitCell spent → must reject (front-running guard).
    assert!(
        verify_full(&[i], &o, b"register", &[], false, None).is_err(),
        "register must spend a matching CommitCell"
    );
}

#[test]
fn register_rejects_young_commit() {
    let (i, o) = register_fixture();
    // The commit exists and matches, but it is one second short of MIN_DELAY.
    let young = Commit { since: rel_ts(COMMIT_MIN_DELAY - 1), ..Commit::good() };
    assert!(
        verify_full(&[i], &o, b"register", &[], false, Some(&young)).is_err(),
        "a commit younger than MIN_DELAY must be rejected"
    );
}

#[test]
fn register_rejects_commit_wrong_since_flag() {
    let (i, o) = register_fixture();
    // Old enough numerically, but absolute (not relative) since → consensus would
    // not actually enforce the delay, so the script must reject the flag.
    let bad = Commit { since: abs_ts(COMMIT_MIN_DELAY), ..Commit::good() };
    assert!(
        verify_full(&[i], &o, b"register", &[], false, Some(&bad)).is_err(),
        "the commit since must be a *relative* timestamp"
    );
}

#[test]
fn register_rejects_past_expiry() {
    // L-2: a name registered already-expired (expired_at well before "now") is
    // rejected, "now" is read from the matured CommitCell's block header.
    let alice = account_id(b"alice");
    let root_w = WitnessData::default();
    let (root_before, _) = account_cell(ROOT_ID, ROOT_ID, 0, b"", &root_w);
    let (root_after, root_after_w) = account_cell(ROOT_ID, alice, 0, b"", &root_w);
    let past = 1_000_000u64; // ≪ the harness "now" (~1.7e9 s)
    let (alice_d, alice_w) = account_cell(alice, ROOT_ID, past, b"alice", &records_witness());
    let outs = vec![
        outc(&root_after, &root_after_w),
        OutC { cap: ALICE_PRICE, ..outc(&alice_d, &alice_w) },
        treasury_out(FEE_1Y), // paid, so the only thing wrong is the expiry
    ];
    let res = verify_full(&[inc(&root_before)], &outs, b"register", &[], false, Some(&Commit::good()));
    assert_code(&res, 39, "a name registered already expired (L-2)");
}

#[test]
fn register_rejects_null_owner() {
    // L-1: a new name with an all-zero owner_lock_hash (un-spendable) is rejected,
    // even with an otherwise-valid commit.
    let (i, mut o) = register_fixture();
    o[1].owner = L::Null;
    assert!(
        verify_full(&[i], &o, b"register", &[], false, Some(&Commit::good())).is_err(),
        "register with an all-zero owner must be rejected (L-1)"
    );
}

/// The other half of L-1, and the one that was open: an owner set to the cell's own
/// always-success lock. `require_owner` looks for an INPUT carrying that lock hash,
/// and every AccountCell carries it, so the name would have been editable and
/// transferable by anyone who touched one.
#[test]
fn register_rejects_owner_set_to_the_cell_lock() {
    let (i, mut o) = register_fixture();
    o[1].owner = L::Acct; // the always-success lock every account cell wears
    let res = verify_full(&[i], &o, b"register", &[], false, Some(&Commit::good()));
    assert_code(&res, 44, "a new name owned by the always-success cell lock");
}

/// The AccountCell's own lock must be the always-success account-lock, the lock every
/// action's inputs wear. A register that puts the new cell under any other lock is
/// refused (error 48). An unspendable lock would freeze the cell's id-range forever
/// (it can never be spent as a predecessor again); a lock equal to the treasury or an
/// inviter would let the cell's own refundable rent be counted as the fee or the
/// referral cut. The suite otherwise always uses L::Acct, so these are the only tests
/// that vary the cell's own lock.
#[test]
fn register_rejects_a_new_cell_under_a_foreign_lock() {
    let (i, mut o) = register_fixture();
    o[1].lock = L::B; // any lock other than the account-lock the predecessor wears
    let res = verify_full(&[i], &o, b"register", &[], false, Some(&Commit::good()));
    assert_code(&res, 48, "a new AccountCell under a lock other than the account-lock");
}

#[test]
fn register_rejects_repointing_the_predecessor_lock() {
    let (i, mut o) = register_fixture();
    o[0].lock = L::B; // the preserved predecessor must keep the account-lock too
    let res = verify_full(&[i], &o, b"register", &[], false, Some(&Commit::good()));
    assert_code(&res, 48, "the preserved predecessor under a foreign lock");
}

#[test]
fn transfer_rejects_a_foreign_cell_lock() {
    let id = account_id(b"alice");
    let (din, _) = account_cell(id, ROOT_ID, FUTURE, b"alice", &records_witness());
    let (dout, pout) = account_cell(id, ROOT_ID, FUTURE, b"alice", &records_witness());
    let i = inc(&din);
    // A cell under a foreign lock, with an ordinary (non-cell-lock) owner so the
    // rejection is the lock pin (48), not the owner-is-cell-lock guard (44).
    let o = OutC { lock: L::B, owner: L::Seq, ..outc(&dout, &pout) };
    let res = verify(&[i], &[o], b"transfer", &[L::A], false);
    assert_code(&res, 48, "transferring a name to a cell under a foreign lock");
}

#[test]
fn transfer_rejects_owner_set_to_the_cell_lock() {
    let id = account_id(b"alice");
    let (din, _) = account_cell(id, ROOT_ID, FUTURE, b"alice", &records_witness());
    let (dout, pout) = account_cell(id, ROOT_ID, FUTURE, b"alice", &records_witness());
    let i = inc(&din);
    let o = OutC { owner: L::Acct, manager: Some(L::Acct), ..outc(&dout, &pout) };
    let res = verify(&[i], &[o], b"transfer", &[L::A], false);
    assert_code(&res, 44, "giving a name to the always-success cell lock");
}

/// Nothing constrained the manager at all, so this was a second way in: a delegate
/// anyone can be is not a delegate.
#[test]
fn set_manager_rejects_manager_set_to_the_cell_lock() {
    let id = account_id(b"alice");
    let w = records_witness();
    let (din, _) = account_cell(id, ROOT_ID, FUTURE, b"alice", &w);
    let (dout, pout) = account_cell_v2(id, ROOT_ID, FUTURE, b"alice", &w);
    let i = inc(&din);
    let o = OutC { manager: Some(L::Acct), ..outc(&dout, &pout) };
    let res = verify(&[i], &[o], b"edit_manager", &[L::A], false);
    assert_code(&res, 44, "delegating to the always-success cell lock");
}

/// White-hat check (not yet in SECURITY.md): `register` and `transfer` both reject an
/// all-zero owner (L-1), but `edit_manager` never runs `reject_null_owner` on the new
/// manager. Reproduced before judging severity: this is owner self-harm, not a hole
/// for anyone else, since only the owner can call `edit_manager` and a null manager is
/// recoverable by the owner calling it again. Written to match the existing
/// `transfer_rejects_null_owner` shape exactly.
#[test]
fn set_manager_rejects_null_manager() {
    let id = account_id(b"alice");
    let w = records_witness();
    let (din, _) = account_cell(id, ROOT_ID, FUTURE, b"alice", &w);
    let (dout, pout) = account_cell_v2(id, ROOT_ID, FUTURE, b"alice", &w);
    let i = inc(&din);
    let o = OutC { manager: Some(L::Null), ..outc(&dout, &pout) };
    let res = verify(&[i], &[o], b"edit_manager", &[L::A], false);
    assert!(res.is_err(), "delegating to the all-zero manager must be rejected, same as L-1 does for owner");
}

#[test]
fn register_rejects_commit_mismatch() {
    let (i, o) = register_fixture();
    // A matured commit is spent, but its commitment does not match the revealed
    // (label, owner, secret) → no input matches → reject. Models a stolen-reveal
    // front-run attempt (the attacker has no matching matured commit).
    let mism = Commit { bad_data: Some(Bytes::from(vec![0xab; 32])), ..Commit::good() };
    assert!(
        verify_full(&[i], &o, b"register", &[], false, Some(&mism)).is_err(),
        "a commit that does not match the revealed name must be rejected"
    );
}

#[test]
fn register_rejects_underpriced() {
    let (i, mut o) = register_fixture();
    o[1].cap = ALICE_PRICE - 1; // one shannon below the flat floor
    // With a real commit, so the failure is the price floor and not a missing
    // commitment. Without it this test passed on error 36 for a long time.
    let res = verify_full(&[i], &o, b"register", &[], false, Some(&Commit::good()));
    assert_code(&res, 35, "a name locking less than the price floor");
}

/// The front-run. A commitment is the commit cell's whole data, so it is public the
/// moment that transaction confirms, a full minute before the reveal. If the contract
/// does not care WHO holds the matching cell, anyone can copy those 32 bytes into a
/// cell of their own, mature it on the same clock, read the secret out of the
/// victim's broadcast reveal, and land the registration first.
#[test]
fn register_rejects_a_commit_held_by_a_stranger() {
    let (i, o) = register_fixture(); // the name is owned by L::A
    let stolen = Commit { holder: L::B, ..Commit::good() }; // held by someone else
    let res = verify_full(&[i], &o, b"register", &[], false, Some(&stolen));
    assert_code(&res, 47, "a commitment copied into a stranger's cell");
}

/// A name is registered undelegated. The commitment does not cover the manager, so
/// whoever lands the registration would otherwise choose it: chained onto the
/// front-run above, that is permanent control of the records on a name that reads as
/// its owner's.
#[test]
fn register_rejects_a_manager_at_registration() {
    let alice = account_id(b"alice");
    let root_w = WitnessData::default();
    let (root_before, _) = account_cell(ROOT_ID, ROOT_ID, 0, b"", &root_w);
    let (root_after, root_after_w) = account_cell(ROOT_ID, alice, 0, b"", &root_w);
    let (d, w) = account_cell_v2(alice, ROOT_ID, FUTURE, b"alice", &records_witness());
    let outs = vec![
        outc(&root_after, &root_after_w),
        OutC { cap: ALICE_PRICE, manager: Some(L::B), ..outc(&d, &w) },
        treasury_out(FEE_1Y),
    ];
    let res = verify_full(&[inc(&root_before)], &outs, b"register", &[], false, Some(&Commit::good()));
    assert!(res.is_err(), "a manager may not be installed at registration, got {res:?}");
}

// --- capacity conservation on the permissionless actions -------------------
//
// `register` guarded the predecessor's capacity from the start. Nothing else did, and
// three of the other actions are permissionless, so a stranger could keep the name
// intact and walk off with the deposit.

#[test]
fn recycle_rejects_predecessor_capacity_skim() {
    let t = 1_000_000;
    let (ins, mut outs) = recycle_inputs(t, abs_ts(t));
    outs[0].cap = CAP - 1; // skim one shannon off an innocent third party
    let res = verify(&ins, &outs, b"recycle", &[], false);
    assert!(res.is_err(), "recycle must not shrink the predecessor, got {res:?}");
}

#[test]
fn renew_rejects_capacity_skim() {
    let id = account_id(b"alice");
    let w = records_witness();
    let (din, _) = account_cell(id, ROOT_ID, FUTURE, b"alice", &w);
    let (dout, pout) = account_cell(id, ROOT_ID, FUTURE + ONE_YEAR, b"alice", &w);
    // Permissionless: a stranger pays the fee and takes the owner's rent with it.
    let outs = [OutC { cap: CAP - 1, ..outc(&dout, &pout) }, treasury_out(FEE_1Y)];
    let res = verify(&[inc(&din)], &outs, b"renew", &[], false);
    assert!(res.is_err(), "renew must not shrink the name's cell, got {res:?}");
}

#[test]
fn edit_rejects_capacity_skim() {
    let id = account_id(b"alice");
    let (din, _) = account_cell(id, ROOT_ID, FUTURE, b"alice", &records_witness());
    // a different record set, so this is a real edit and not a no-op
    let w = WitnessData {
        records: vec![RecordEntry {
            key: b"address.309".to_vec(),
            label: b"".to_vec(),
            value: b"ckt1qskimmed".to_vec(),
            ttl: 300,
        }],
    };
    let (dout, pout) = account_cell(id, ROOT_ID, FUTURE, b"alice", &w);
    // A delegate whose whole remit is "may edit records" could empty the cell.
    let o = OutC { cap: CAP - 1, ..outc(&dout, &pout) };
    let res = verify(&[inc(&din)], &[o], b"edit_records", &[L::A], false);
    assert!(res.is_err(), "an edit must not shrink the name's cell, got {res:?}");
}

// --- the term, and the fee that comes with it (decision 0009) --------------

#[test]
fn register_rejects_an_unpaid_fee() {
    let (i, mut o) = register_fixture();
    o.pop(); // drop the treasury output
    let res = verify_full(&[i], &o, b"register", &[], false, Some(&Commit::good()));
    assert_code(&res, 42, "registration without paying the treasury");
}

#[test]
fn register_rejects_a_fee_that_is_one_shannon_short() {
    let (i, mut o) = register_fixture();
    let last = o.len() - 1;
    o[last].cap = FEE_1Y - 1;
    let res = verify_full(&[i], &o, b"register", &[], false, Some(&Commit::good()));
    assert_code(&res, 42, "a fee one shannon short");
}

/// The rent stays in the registrant's own cell and the fee leaves for good, so
/// paying one cannot count as paying the other. Locking the rent twice over buys
/// nothing if the treasury sees none of it.
#[test]
fn the_rent_is_not_the_fee() {
    let (i, mut o) = register_fixture();
    o.pop();
    o[1].cap = ALICE_PRICE + FEE_1Y;
    let res = verify_full(&[i], &o, b"register", &[], false, Some(&Commit::good()));
    assert_code(&res, 42, "rent inflated in place of a fee");
}

/// Splitting the payment across outputs is allowed: the check is a sum, so a client
/// is free to build the transaction however suits it.
#[test]
fn a_fee_may_arrive_in_pieces() {
    let (i, mut o) = register_fixture();
    o.pop();
    o.push(treasury_out(FEE_1Y / 3));
    o.push(treasury_out(FEE_1Y - FEE_1Y / 3));
    let res = verify_full(&[i], &o, b"register", &[], false, Some(&Commit::good()));
    assert!(res.is_ok(), "a fee split over two outputs should pass, got {res:?}");
}

#[test]
fn register_rejects_a_term_under_a_year() {
    let alice = account_id(b"alice");
    let root_w = WitnessData::default();
    let (root_before, _) = account_cell(ROOT_ID, ROOT_ID, 0, b"", &root_w);
    let (root_after, root_after_w) = account_cell(ROOT_ID, alice, 0, b"", &root_w);
    // A day short of a year: the old rule (a one-day floor) would have allowed this.
    let (d, w) = account_cell(alice, ROOT_ID, NOW + ONE_YEAR - 86_400, b"alice", &records_witness());
    let outs = vec![
        outc(&root_after, &root_after_w),
        OutC { cap: ALICE_PRICE, ..outc(&d, &w) },
        treasury_out(FEE_1Y),
    ];
    let res = verify_full(&[inc(&root_before)], &outs, b"register", &[], false, Some(&Commit::good()));
    assert_code(&res, 39, "a term of under a year");
}

#[test]
fn register_rejects_a_term_over_ten_years() {
    let alice = account_id(b"alice");
    let root_w = WitnessData::default();
    let (root_before, _) = account_cell(ROOT_ID, ROOT_ID, 0, b"", &root_w);
    let (root_after, root_after_w) = account_cell(ROOT_ID, alice, 0, b"", &root_w);
    // The year 2096, which is what `register` used to default to.
    let (d, w) = account_cell(alice, ROOT_ID, 4_000_000_000, b"alice", &records_witness());
    let outs = vec![
        outc(&root_after, &root_after_w),
        OutC { cap: ALICE_PRICE, ..outc(&d, &w) },
        treasury_out(100 * FEE_1Y), // paid generously; still refused
    ];
    let res = verify_full(&[inc(&root_before)], &outs, b"register", &[], false, Some(&Commit::good()));
    assert_code(&res, 43, "a seventy-year term");
}

#[test]
fn register_charges_by_the_year() {
    let alice = account_id(b"alice");
    let root_w = WitnessData::default();
    let (root_before, _) = account_cell(ROOT_ID, ROOT_ID, 0, b"", &root_w);
    let (root_after, root_after_w) = account_cell(ROOT_ID, alice, 0, b"", &root_w);
    let (d, w) = account_cell(alice, ROOT_ID, NOW + 5 * ONE_YEAR, b"alice", &records_witness());
    let build = |fee: u64| {
        vec![
            outc(&root_after, &root_after_w),
            OutC { cap: ALICE_PRICE, ..outc(&d, &w) },
            treasury_out(fee),
        ]
    };
    // Five years are charged as four: the fifth is the free year, so paying four is
    // paying in full, and paying three is short.
    assert_code(
        &verify_full(&[inc(&root_before)], &build(3 * FEE_1Y), b"register", &[], false, Some(&Commit::good())),
        42,
        "five years paid as three",
    );
    let res = verify_full(&[inc(&root_before)], &build(4 * FEE_1Y), b"register", &[], false, Some(&Commit::good()));
    assert!(res.is_ok(), "five years paid as four should pass, got {res:?}");
}

/// The free year, at the term a price list would quote: ten years for the price of
/// eight, refused at seven.
#[test]
fn ten_years_are_charged_as_eight_on_chain() {
    let alice = account_id(b"alice");
    let root_w = WitnessData::default();
    let (root_before, _) = account_cell(ROOT_ID, ROOT_ID, 0, b"", &root_w);
    let (root_after, root_after_w) = account_cell(ROOT_ID, alice, 0, b"", &root_w);
    let (d, w) = account_cell(alice, ROOT_ID, NOW + 10 * ONE_YEAR, b"alice", &records_witness());
    let build = |fee: u64| {
        vec![
            outc(&root_after, &root_after_w),
            OutC { cap: ALICE_PRICE, ..outc(&d, &w) },
            treasury_out(fee),
        ]
    };
    assert_code(
        &verify_full(&[inc(&root_before)], &build(7 * FEE_1Y), b"register", &[], false, Some(&Commit::good())),
        42,
        "ten years paid as seven",
    );
    let res = verify_full(&[inc(&root_before)], &build(8 * FEE_1Y), b"register", &[], false, Some(&Commit::good()));
    assert!(res.is_ok(), "ten years paid as eight should pass, got {res:?}");
}

#[test]
fn register_rejects_mismatched_id() {
    let bob = account_id(b"bob");
    let (root_before, _) = account_cell(ROOT_ID, ROOT_ID, 0, b"", &WitnessData::default());
    let (root_after, raw) = account_cell(ROOT_ID, bob, 0, b"", &WitnessData::default());
    let (bad, bad_w) = account_cell(bob, ROOT_ID, FUTURE, b"alice", &records_witness());
    let outs = vec![outc(&root_after, &raw), outc(&bad, &bad_w)];
    assert!(verify(&[inc(&root_before)], &outs, b"register", &[], false).is_err());
}

#[test]
fn register_rejects_invalid_label() {
    // "Alice" (uppercase): id-integrity passes (id == blake2b("Alice")) but the
    // on-chain charset check must still reject it.
    let bad = account_id(b"Alice");
    let root_w = WitnessData::default();
    let (root_before, _) = account_cell(ROOT_ID, ROOT_ID, 0, b"", &root_w);
    let (root_after, raw) = account_cell(ROOT_ID, bad, 0, b"", &root_w);
    let (x, xw) = account_cell(bad, ROOT_ID, FUTURE, b"Alice", &records_witness());
    let outs = vec![outc(&root_after, &raw), outc(&x, &xw)];
    assert!(
        verify(&[inc(&root_before)], &outs, b"register", &[], false).is_err(),
        "an invalid label must be rejected on-chain"
    );
}

#[test]
fn register_rejects_tampered_new_witness() {
    let (i, mut o) = register_fixture();
    let mut bad = o[1].witness.to_vec();
    bad.push(0xff);
    o[1].witness = Bytes::from(bad);
    assert!(verify(&[i], &o, b"register", &[], false).is_err());
}

#[test]
fn register_rejects_predecessor_owner_tamper() {
    // The splice is valid, but the attacker rewrites the predecessor's owner.
    let (i, mut o) = register_fixture();
    o[0].owner = L::B; // predecessor (root) owner changed away from the input's
    assert!(
        verify(&[i], &o, b"register", &[], false).is_err(),
        "must not rewrite the predecessor's owner"
    );
}

#[test]
fn register_rejects_predecessor_capacity_skim() {
    let (i, mut o) = register_fixture();
    o[0].cap = CAP - 1; // skim 1 shannon off the predecessor
    assert!(
        verify(&[i], &o, b"register", &[], false).is_err(),
        "must not shrink the predecessor's capacity"
    );
}

#[test]
fn rejects_unknown_action() {
    let (i, o) = register_fixture();
    assert!(verify(&[i], &o, b"frobnicate", &[], false).is_err());
}

// --- edit_records / edit_manager (owner-gated) -----------------------------

fn alice_edit(records: Vec<RecordEntry>) -> (InC, OutC) {
    let id = account_id(b"alice");
    let (din, _) = account_cell(id, ROOT_ID, FUTURE, b"alice", &records_witness());
    let w = WitnessData { records };
    let (dout, pout) = account_cell(id, ROOT_ID, FUTURE, b"alice", &w);
    (inc(&din), outc(&dout, &pout))
}

#[test]
fn edit_records_ok_with_owner_cosign() {
    let (i, o) = alice_edit(vec![RecordEntry {
        key: b"address.60".to_vec(),
        label: vec![],
        value: vec![1, 2, 3],
        ttl: 300,
    }]);
    // owner = A (default); co-sign with an A-locked input.
    let res = verify(&[i], &[o], b"edit_records", &[L::A], false);
    assert!(res.is_ok(), "edit with owner co-sign should pass, got {res:?}");
}

#[test]
fn edit_rejects_without_owner_cosign() {
    let (i, o) = alice_edit(vec![RecordEntry {
        key: b"address.60".to_vec(),
        label: vec![],
        value: vec![1, 2, 3],
        ttl: 300,
    }]);
    let res = verify(&[i], &[o], b"edit_records", &[], false);
    assert!(res.is_err(), "edit must require the owner's co-sign");
}

#[test]
fn edit_rejects_wrong_owner_cosign() {
    let (i, o) = alice_edit(vec![]);
    // co-sign with B, but the account is owned by A.
    let res = verify(&[i], &[o], b"edit_records", &[L::B], false);
    assert!(res.is_err(), "a non-owner co-sign must not authorize an edit");
}

#[test]
fn edit_rejects_lock_change() {
    let (i, mut o) = alice_edit(vec![]);
    o.lock = L::B; // the uniform cell lock must not change
    let res = verify(&[i], &[o], b"edit_records", &[L::A], false);
    assert!(res.is_err(), "edit must not change the cell lock");
}

#[test]
fn edit_rejects_owner_change() {
    let (i, mut o) = alice_edit(vec![]);
    o.owner = L::B; // owner_lock_hash must not change under edit
    let res = verify(&[i], &[o], b"edit_records", &[L::A], false);
    assert!(res.is_err(), "edit must not change owner_lock_hash");
}

#[test]
fn edit_rejects_expiry_change() {
    let id = account_id(b"alice");
    let (din, _) = account_cell(id, ROOT_ID, FUTURE, b"alice", &records_witness());
    let (dout, pout) = account_cell(id, ROOT_ID, FUTURE + 1, b"alice", &records_witness());
    let res = verify(&[inc(&din)], &[outc(&dout, &pout)], b"edit_records", &[L::A], false);
    assert!(res.is_err(), "edit must not change expired_at");
}

// --- transfer (owner-gated; changes owner_lock_hash) -----------------------

#[test]
fn transfer_changes_owner_ok() {
    let id = account_id(b"alice");
    let (din, _) = account_cell(id, ROOT_ID, FUTURE, b"alice", &records_witness());
    let (dout, pout) = account_cell(id, ROOT_ID, FUTURE, b"alice", &records_witness());
    let out = OutC { owner: L::B, ..outc(&dout, &pout) }; // hand to owner B
    // current owner (A) authorizes.
    let res = verify(&[inc(&din)], &[out], b"transfer", &[L::A], false);
    assert!(res.is_ok(), "transfer with current-owner co-sign should pass, got {res:?}");
}

#[test]
fn transfer_rejects_without_current_owner() {
    let id = account_id(b"alice");
    let (din, _) = account_cell(id, ROOT_ID, FUTURE, b"alice", &records_witness());
    let (dout, pout) = account_cell(id, ROOT_ID, FUTURE, b"alice", &records_witness());
    let out = OutC { owner: L::B, ..outc(&dout, &pout) };
    // co-sign with the *new* owner B, must not authorize giving the name away.
    let res = verify(&[inc(&din)], &[out], b"transfer", &[L::B], false);
    assert!(res.is_err(), "transfer must be authorized by the *current* owner");
}

#[test]
fn transfer_rejects_null_owner() {
    // L-1: the current owner authorizes, but the new owner is the all-zero hash, 
    // transferring a name into an un-spendable state is rejected.
    let id = account_id(b"alice");
    let (din, _) = account_cell(id, ROOT_ID, FUTURE, b"alice", &records_witness());
    let (dout, pout) = account_cell(id, ROOT_ID, FUTURE, b"alice", &records_witness());
    let out = OutC { owner: L::Null, ..outc(&dout, &pout) };
    let res = verify(&[inc(&din)], &[out], b"transfer", &[L::A], false);
    assert!(res.is_err(), "transfer to an all-zero owner must be rejected (L-1)");
}

/// A transfer hands over the name as it stands. The records travel with it, so what a
/// name publishes cannot be dropped or swapped by whoever assembles the transaction:
/// buying the name that had the picture gets you the picture.
#[test]
fn transfer_carries_the_records_across() {
    let id = account_id(b"alice");
    let w = WitnessData {
        records: vec![RecordEntry {
            key: b"profile.avatar".to_vec(),
            label: vec![],
            value: vec![0x89, 0x50, 0x4e, 0x47, 7, 7, 7],
            ttl: 300,
        }],
    };
    let (din, _) = account_cell(id, ROOT_ID, FUTURE, b"alice", &w);
    let (dout, pout) = account_cell(id, ROOT_ID, FUTURE, b"alice", &w);
    let out = OutC { owner: L::B, ..outc(&dout, &pout) };
    let res = verify(&[inc(&din)], &[out], b"transfer", &[L::A], false);
    assert!(res.is_ok(), "a transfer carrying the same records should pass, got {res:?}");
}

#[test]
fn transfer_rejects_dropping_the_records() {
    // The case this rule exists for: the name is handed over with its picture removed.
    let id = account_id(b"alice");
    let w = WitnessData {
        records: vec![RecordEntry {
            key: b"profile.avatar".to_vec(),
            label: vec![],
            value: vec![0x89, 0x50, 0x4e, 0x47, 7, 7, 7],
            ttl: 300,
        }],
    };
    let (din, _) = account_cell(id, ROOT_ID, FUTURE, b"alice", &w);
    let (dout, pout) = account_cell(id, ROOT_ID, FUTURE, b"alice", &records_witness()); // emptied
    let out = OutC { owner: L::B, ..outc(&dout, &pout) };
    let res = verify(&[inc(&din)], &[out], b"transfer", &[L::A], false);
    assert!(res.is_err(), "a transfer must not drop the name's records");
}

#[test]
fn transfer_rejects_swapping_the_records() {
    // And it must not substitute different ones, which is the same attack wearing a hat.
    let id = account_id(b"alice");
    let mk = |v: Vec<u8>| WitnessData {
        records: vec![RecordEntry { key: b"profile.avatar".to_vec(), label: vec![], value: v, ttl: 300 }],
    };
    let (din, _) = account_cell(id, ROOT_ID, FUTURE, b"alice", &mk(vec![0x89, 0x50, 0x4e, 0x47, 1]));
    let (dout, pout) = account_cell(id, ROOT_ID, FUTURE, b"alice", &mk(vec![0x89, 0x50, 0x4e, 0x47, 2]));
    let out = OutC { owner: L::B, ..outc(&dout, &pout) };
    let res = verify(&[inc(&din)], &[out], b"transfer", &[L::A], false);
    assert!(res.is_err(), "a transfer must not substitute different records");
}

#[test]
fn transfer_rejects_account_change() {
    let id = account_id(b"alice");
    let other = account_id(b"alicex");
    let (din, _) = account_cell(id, ROOT_ID, FUTURE, b"alice", &records_witness());
    let (dout, pout) = account_cell(other, ROOT_ID, FUTURE, b"alicex", &records_witness());
    let res = verify(&[inc(&din)], &[outc(&dout, &pout)], b"transfer", &[L::A], false);
    assert!(res.is_err(), "transfer must not change the account label");
}

// --- manager delegation (v2, decision 0006) --------------------------------

#[test]
fn edit_records_ok_by_manager() {
    // v2 cell: owner A, manager B. The MANAGER may edit records.
    let id = account_id(b"alice");
    let (din, _) = account_cell_v2(id, ROOT_ID, FUTURE, b"alice", &records_witness());
    let w = WitnessData {
        records: vec![RecordEntry { key: b"address.60".to_vec(), label: vec![], value: vec![1, 2, 3], ttl: 300 }],
    };
    let (dout, pout) = account_cell_v2(id, ROOT_ID, FUTURE, b"alice", &w);
    let i = InC { manager: Some(L::B), ..inc(&din) };
    let o = OutC { manager: Some(L::B), ..outc(&dout, &pout) };
    let res = verify(&[i], &[o], b"edit_records", &[L::B], false);
    assert!(res.is_ok(), "the manager may edit records, got {res:?}");
}

#[test]
fn edit_rejects_by_stranger_on_v2() {
    let id = account_id(b"alice");
    let (din, _) = account_cell_v2(id, ROOT_ID, FUTURE, b"alice", &records_witness());
    let (dout, pout) = account_cell_v2(id, ROOT_ID, FUTURE, b"alice", &records_witness());
    let i = InC { manager: Some(L::B), ..inc(&din) }; // owner A, manager B
    let o = OutC { manager: Some(L::B), ..outc(&dout, &pout) };
    // Seq is neither owner nor manager.
    let res = verify(&[i], &[o], b"edit_records", &[L::Seq], false);
    assert!(res.is_err(), "a non-owner, non-manager must not edit records");
}

#[test]
fn set_manager_by_owner_migrates_v1_to_v2() {
    // Owner of a v1 name delegates a manager → the cell migrates to v2.
    let id = account_id(b"alice");
    let w = records_witness();
    let (din, _) = account_cell(id, ROOT_ID, FUTURE, b"alice", &w); // v1 input
    let (dout, pout) = account_cell_v2(id, ROOT_ID, FUTURE, b"alice", &w); // v2 output
    let i = inc(&din); // owner A (manager defaults to A)
    let o = OutC { manager: Some(L::B), ..outc(&dout, &pout) }; // owner A, manager B
    let res = verify(&[i], &[o], b"edit_manager", &[L::A], false);
    assert!(res.is_ok(), "owner sets a manager, migrating v1→v2, got {res:?}");
}

#[test]
fn set_manager_rejects_by_manager() {
    // The manager cannot re-delegate, only the owner may change the manager.
    let id = account_id(b"alice");
    let w = records_witness();
    let (din, _) = account_cell_v2(id, ROOT_ID, FUTURE, b"alice", &w);
    let (dout, pout) = account_cell_v2(id, ROOT_ID, FUTURE, b"alice", &w);
    let i = InC { manager: Some(L::B), ..inc(&din) }; // owner A, manager B
    let o = OutC { manager: Some(L::Seq), ..outc(&dout, &pout) }; // tries manager → Seq
    let res = verify(&[i], &[o], b"edit_manager", &[L::B], false); // co-signed by the manager
    assert!(res.is_err(), "only the owner may set the manager");
}

#[test]
fn transfer_resets_manager_ok() {
    // A delegated v2 name, transferred: the manager is reset to the new owner.
    let id = account_id(b"alice");
    let w = records_witness();
    let (din, _) = account_cell_v2(id, ROOT_ID, FUTURE, b"alice", &w);
    let (dout, pout) = account_cell_v2(id, ROOT_ID, FUTURE, b"alice", &w);
    let i = InC { manager: Some(L::B), ..inc(&din) }; // owner A, manager B
    let o = OutC { owner: L::B, manager: Some(L::B), ..outc(&dout, &pout) }; // owner B, manager reset to B
    let res = verify(&[i], &[o], b"transfer", &[L::A], false);
    assert!(res.is_ok(), "transfer resets the manager to the new owner, got {res:?}");
}

#[test]
fn transfer_rejects_manager_not_reset() {
    let id = account_id(b"alice");
    let w = records_witness();
    let (din, _) = account_cell_v2(id, ROOT_ID, FUTURE, b"alice", &w);
    let (dout, pout) = account_cell_v2(id, ROOT_ID, FUTURE, b"alice", &w);
    let i = InC { manager: Some(L::B), ..inc(&din) };
    let o = OutC { owner: L::B, manager: Some(L::Seq), ..outc(&dout, &pout) }; // manager NOT reset
    let res = verify(&[i], &[o], b"transfer", &[L::A], false);
    assert!(res.is_err(), "transfer must reset the manager to the new owner");
}

// --- renew (permissionless) ------------------------------------------------

#[test]
fn renew_extends_ok() {
    let id = account_id(b"alice");
    let w = records_witness();
    let (din, _) = account_cell(id, ROOT_ID, FUTURE, b"alice", &w);
    let (dout, pout) = account_cell(id, ROOT_ID, FUTURE + 1000, b"alice", &w);
    // permissionless: no co-sign. Paid, though: a part-year extension buys a whole
    // year, so a thousand seconds costs the same as twelve months.
    let outs = [outc(&dout, &pout), treasury_out(FEE_1Y)];
    let res = verify(&[inc(&din)], &outs, b"renew", &[], false);
    assert!(res.is_ok(), "renew should pass, got {res:?}");
}

#[test]
fn renew_rejects_an_unpaid_extension() {
    let id = account_id(b"alice");
    let w = records_witness();
    let (din, _) = account_cell(id, ROOT_ID, FUTURE, b"alice", &w);
    let (dout, pout) = account_cell(id, ROOT_ID, FUTURE + ONE_YEAR, b"alice", &w);
    let res = verify(&[inc(&din)], &[outc(&dout, &pout)], b"renew", &[], false);
    assert_code(&res, 42, "renewal without paying the treasury");
}

#[test]
fn renew_charges_for_every_year() {
    let id = account_id(b"alice");
    let w = records_witness();
    let (din, _) = account_cell(id, ROOT_ID, FUTURE, b"alice", &w);
    // Three years on: three years of fee, and two will not do.
    let (dout, pout) = account_cell(id, ROOT_ID, FUTURE + 3 * ONE_YEAR, b"alice", &w);
    let short = [outc(&dout, &pout), treasury_out(2 * FEE_1Y)];
    assert_code(
        &verify(&[inc(&din)], &short, b"renew", &[], false),
        42,
        "three years paid as two",
    );
    let exact = [outc(&dout, &pout), treasury_out(3 * FEE_1Y)];
    let res = verify(&[inc(&din)], &exact, b"renew", &[], false);
    assert!(res.is_ok(), "three years paid in full should pass, got {res:?}");
}

#[test]
fn renew_rejects_more_than_ten_years_at_once() {
    let id = account_id(b"alice");
    let w = records_witness();
    let (din, _) = account_cell(id, ROOT_ID, FUTURE, b"alice", &w);
    let (dout, pout) = account_cell(id, ROOT_ID, FUTURE + 11 * ONE_YEAR, b"alice", &w);
    // Paid in full, and still refused: the cap is on the term, not on the money.
    let outs = [outc(&dout, &pout), treasury_out(11 * FEE_1Y)];
    assert_code(&verify(&[inc(&din)], &outs, b"renew", &[], false), 43, "an eleven-year renewal");
}

#[test]
fn renew_rejects_shrink() {
    let id = account_id(b"alice");
    let w = records_witness();
    let (din, _) = account_cell(id, ROOT_ID, FUTURE, b"alice", &w);
    let (dout, pout) = account_cell(id, ROOT_ID, FUTURE - 1000, b"alice", &w);
    let res = verify(&[inc(&din)], &[outc(&dout, &pout)], b"renew", &[], false);
    assert!(res.is_err(), "renew must not shrink expired_at");
}

#[test]
fn renew_rejects_owner_change() {
    let id = account_id(b"alice");
    let w = records_witness();
    let (din, _) = account_cell(id, ROOT_ID, FUTURE, b"alice", &w);
    let (dout, pout) = account_cell(id, ROOT_ID, FUTURE + 1000, b"alice", &w);
    let out = OutC { owner: L::B, ..outc(&dout, &pout) }; // renew must not steal ownership
    let res = verify(&[inc(&din)], &[out], b"renew", &[], false);
    assert!(res.is_err(), "renew must not change owner_lock_hash");
}

// --- recycle (permissionless cleanup of expired names) ---------------------

fn recycle_inputs(old_expired: u64, x_since: u64) -> (Vec<InC>, Vec<OutC>) {
    // list: root -> old -> (wrap). Recycle "old".
    let old = account_id(b"old");
    let root_w = WitnessData::default();
    let (root_before, _) = account_cell(ROOT_ID, old, 0, b"", &root_w);
    let (old_d, _) = account_cell(old, ROOT_ID, old_expired, b"old", &records_witness());
    let (root_after, root_after_w) = account_cell(ROOT_ID, ROOT_ID, 0, b"", &root_w);
    (
        vec![inc(&root_before), InC { since: x_since, ..inc(&old_d) }],
        vec![outc(&root_after, &root_after_w)],
    )
}

#[test]
fn recycle_expired_ok() {
    let t = 1_000_000;
    // Past expiry AND past the grace period: the ordinary case.
    let (ins, outs) = recycle_inputs(t, abs_ts(t + 30 * 86_400));
    let res = verify(&ins, &outs, b"recycle", &[], false);
    assert!(res.is_ok(), "recycle of an expired name should pass, got {res:?}");
}

/// The root sentinel must never be recyclable.
///
/// It is the one cell exempt from the id-derivation check (`main.rs`: `if a.id() !=
/// ROOT_ID`), which is safe ONLY while id 0 is permanently occupied, because then no
/// live node's range contains it. Remove the root and that exemption becomes a
/// licence to mint a cell with id 0 and any label at all, including one that already
/// exists. The live root also carries `expired_at = 0`, so its expiry proof is free.
///
/// list: root(0 -> old) -> old(old -> 0). To recycle the ROOT, the predecessor is
/// `old`, whose next is 0, and the survivor is `old` with next = root.next = old,
/// a self-loop that is still a structurally valid ring.
#[test]
fn recycle_must_not_remove_the_root() {
    let old = account_id(b"old");
    let root_w = WitnessData::default();
    let (root_d, _) = account_cell(ROOT_ID, old, 0, b"", &root_w);
    let (old_before, _) = account_cell(old, ROOT_ID, FUTURE, b"old", &records_witness());
    let (old_after, old_after_w) = account_cell(old, old, FUTURE, b"old", &records_witness());
    let ins = vec![inc(&old_before), InC { since: abs_ts(1_000_000), ..inc(&root_d) }];
    let outs = vec![outc(&old_after, &old_after_w)];
    let res = verify(&ins, &outs, b"recycle", &[], false);
    assert!(res.is_err(), "the root must not be recyclable, got {res:?}");
}

// The R-1 register-side test that used to sit here ("id 0, label old") described a
// v1-layout forgery the v3 layout cannot express, since the id is derived from the
// label; it died on error 24 and stayed green with the guard deleted (pass 7, P7-3).
// The guard is now pinned by `the_v3_layout_cannot_express_the_r1_forgery_at_all` and
// `register_refuses_the_empty_label_even_where_the_ring_admits_id_zero` below.

/// The grace period, at both edges. A name does not become anybody's the second it
/// lapses: recycling is permissionless, so without this the first forgotten renewal
/// would have been taken by whoever was watching. Thirty days, and the boundary is
/// tested from both sides because a constant with no test is a wish.
#[test]
fn recycle_rejects_a_name_inside_its_grace_period() {
    let t = 1_000_000;
    // One day after expiry: lapsed, but still the owner's.
    let (ins, outs) = recycle_inputs(t, abs_ts(t + 86_400));
    let res = verify(&ins, &outs, b"recycle", &[], false);
    assert!(res.is_err(), "a name one day past expiry must still be safe, got {res:?}");
}

#[test]
fn recycle_allows_a_name_past_its_grace_period() {
    let t = 1_000_000;
    // Thirty days and a second: now it is fair game.
    let (ins, outs) = recycle_inputs(t, abs_ts(t + 30 * 86_400 + 1));
    let res = verify(&ins, &outs, b"recycle", &[], false);
    assert!(res.is_ok(), "a name past its grace period must be recyclable, got {res:?}");
}

#[test]
fn recycle_rejects_not_expired() {
    let t = 1_000_000;
    // since carries the wrong flag -> not proven expired.
    let (ins, outs) = recycle_inputs(t, 0);
    let res = verify(&ins, &outs, b"recycle", &[], false);
    assert!(res.is_err(), "recycle without a valid expiry `since` must be rejected");
}

// --- the price tag (decision 0014) --------------------------------------------
//
// The schedule is a ceiling; a price cell presented as a dep may discount it. What
// is tested here is the read side: the factor is honoured, underpaying it is
// refused, and every way of not presenting a good price cell (absent, malformed,
// out of band) falls back to the FULL price, so a mistake costs the payer and never
// the treasury. The cell's own rules are in price_cell.rs.

fn price_bytes(bps: u32) -> Bytes {
    Bytes::from(cells_core::price_data(bps).to_vec())
}

/// `register_fixture`, paying `treasury` instead of the full fee, with an optional
/// price cell as a dep.
fn priced_register(treasury: u64, price: Option<&Bytes>) -> Result<u64, String> {
    let (i, mut o) = register_fixture();
    o.pop();
    o.push(treasury_out(treasury));
    verify_priced(&[i], &o, b"register", &[], false, Some(&Commit::good()), None, price)
}

#[test]
fn a_price_cell_discounts_the_fee() {
    priced_register(FEE_1Y / 2, Some(&price_bytes(5_000))).expect("half price at factor 5000");
    priced_register(FEE_1Y, Some(&price_bytes(10_000))).expect("at the ceiling the schedule applies");
    priced_register(FEE_1Y, Some(&price_bytes(5_000))).expect("paying more than the discount is allowed");
    // The floor: 5 000 CKB x 126 / 10 000 = 63 CKB, the smallest treasury output.
    priced_register(63 * 100_000_000, Some(&price_bytes(126))).expect("the floor is 63 CKB");
    assert_code(&priced_register(62 * 100_000_000, Some(&price_bytes(126))), 42, "a coin under the floor");
}

#[test]
fn underpaying_the_discounted_fee_is_refused() {
    assert_code(&priced_register(FEE_1Y / 2 - 1, Some(&price_bytes(5_000))), 42, "a shannon under half");
}

#[test]
fn without_a_price_cell_the_full_fee_is_due() {
    // The fail-safe direction: no dep means the ceiling, never a free name.
    assert_code(&priced_register(FEE_1Y / 2, None), 42, "half the fee with no price cell");
    priced_register(FEE_1Y, None).expect("the full fee with no price cell");
}

#[test]
fn a_bad_price_cell_means_the_full_fee() {
    let mut v2 = cells_core::price_data(5_000);
    v2[0] = 2;
    let bad: Vec<(&str, Bytes)> = vec![
        ("junk", Bytes::from_static(b"junk")),
        ("empty", Bytes::new()),
        ("short", Bytes::from(cells_core::price_data(5_000)[..4].to_vec())),
        ("unknown version", Bytes::from(v2.to_vec())),
        ("below the floor", price_bytes(125)),
        ("above the ceiling", price_bytes(10_001)),
        ("zero", price_bytes(0)),
    ];
    for (what, b) in &bad {
        assert_code(&priced_register(FEE_1Y / 2, Some(b)), 42, &format!("half the fee with a {what} price cell"));
        priced_register(FEE_1Y, Some(b)).unwrap_or_else(|e| panic!("the full fee with a {what} price cell should pass, got {e}"));
    }
}

#[test]
fn renew_honours_the_price_cell() {
    let id = account_id(b"alice");
    let w = records_witness();
    let (din, _) = account_cell(id, ROOT_ID, FUTURE, b"alice", &w);
    let (dout, pout) = account_cell(id, ROOT_ID, FUTURE + 1000, b"alice", &w);
    let half = [outc(&dout, &pout), treasury_out(FEE_1Y / 2)];
    verify_priced(&[inc(&din)], &half, b"renew", &[], false, None, None, Some(&price_bytes(5_000)))
        .expect("a renewal at half price");
    assert_code(
        &verify_priced(&[inc(&din)], &half, b"renew", &[], false, None, None, None),
        42,
        "half a year's fee with no price cell",
    );
}

#[test]
fn the_referral_is_a_tenth_of_the_discounted_fee() {
    // Factor 5000: the fee is 2 500, the inviter's tenth is 250, the treasury gets 2 250.
    let fee = FEE_1Y / 2;
    let cut = fee / 10;
    let (i, o) = referral_fixture(fee - cut, L::B, cut);
    verify_priced(&[i], &o, b"register", &[], false, Some(&Commit::good()), Some((&inviter_cell(), L::B)), Some(&price_bytes(5_000)))
        .expect("the tenth comes off the discounted fee");
    let (i, o) = referral_fixture(fee - cut - 1, L::B, cut);
    assert_code(
        &verify_priced(&[i], &o, b"register", &[], false, Some(&Commit::good()), Some((&inviter_cell(), L::B)), Some(&price_bytes(5_000))),
        42,
        "the treasury short by a shannon after the cut",
    );
}

// --- decision 0015: one layout, a version byte first --------------------------
//
// The v1/v2 split is gone, and with it the argument that a label's first byte is
// never 0x02. What replaces it is a version byte at offset 0 that every cell must
// carry. These check that it is enforced on outputs, on both sides of the value.

/// An otherwise valid cell with its version byte replaced.
fn with_version(data: &Bytes, v: u8) -> Bytes {
    let mut d = data.to_vec();
    d[OFF_VERSION] = v;
    Bytes::from(d)
}

#[test]
fn an_output_carrying_the_old_version_byte_is_refused() {
    let (d, w) = account_cell(account_id(b"alice"), ROOT_ID, FUTURE, b"alice", &records_witness());
    let res = verify(&[inc(&d)], &[outc(&with_version(&d, 0x02), &w)], b"edit_records", &[L::A], false);
    assert_code(&res, 20, "a cell not carrying VERSION_V3");
}

// --- pass 7 (2026-09-11): shapes the suite never built -------------------------
//
// Every root in this file is created and spent with `owner: L::A`, because `outc`
// defaults to it. The production root carries ROOT_OWNER (all zero), and R-5 pinned
// the root's length and empty label but never its owner or manager. So the harness
// has been proving genesis against a root the protocol never mints, and nothing
// checked that the contract refuses the other one.

/// The control: the root as the protocol actually mints it, no owner and no manager.
#[test]
fn genesis_creates_the_ownerless_root() {
    let (root_d, root_w) = account_cell(ROOT_ID, ROOT_ID, 0, b"", &WitnessData::default());
    let o = OutC { owner: L::Null, ..outc(&root_d, &root_w) };
    let res = verify(&[], &[o], b"", &[], true);
    assert!(res.is_ok(), "genesis of the ownerless root should pass, got {res:?}");
}

/// A root with an owner is a root somebody can `edit_records`, `edit_manager` and
/// `transfer`, and, more to the point, name as a referral inviter: every registrant
/// could then route a tenth of the fee to that owner instead of the treasury. The
/// sentinel is not a name and must not be one. Genesis is one-shot and token-gated,
/// so this is a deploy-time shape check, the same class as R-5.
#[test]
fn genesis_rejects_a_root_with_an_owner() {
    let (root_d, root_w) = account_cell(ROOT_ID, ROOT_ID, 0, b"", &WitnessData::default());
    let o = OutC { owner: L::A, ..outc(&root_d, &root_w) }; // owner A, manager A
    let res = verify(&[], &[o], b"", &[], true);
    assert_code(&res, 20, "a root sentinel carrying an owner");
}

/// The records payload of output AccountCell `i` is read from `witnesses[i]` through
/// `Source::Input`. `ckb-script` 0.119 resolves that as a plain `witnesses.get(i)`
/// (syscalls/load_witness.rs, `fetch_witness`), unbounded by the input count, so an
/// AccountCell placed past the last input still finds its payload. Nothing in the
/// suite ever put an AccountCell output at an index >= inputs.len(); this does.
#[test]
fn renew_reads_the_witness_by_output_index_past_the_input_count() {
    let id = account_id(b"alice");
    let w = records_witness();
    let (din, _) = account_cell(id, ROOT_ID, FUTURE, b"alice", &w);
    let (dout, pout) = account_cell(id, ROOT_ID, FUTURE + 1000, b"alice", &w);
    // One input; the AccountCell is output 1, so its witness index is 1 >= 1.
    let outs = [treasury_out(FEE_1Y), outc(&dout, &pout)];
    let res = verify(&[inc(&din)], &outs, b"renew", &[], false);
    assert!(res.is_ok(), "a witness past the input count must still be readable, got {res:?}");
}

/// `validate_recycle` decides which input is the predecessor by matching the output's
/// id, so the order of the two inputs must not matter. Every recycle fixture lists
/// the predecessor first; a hostile or merely different client may not.
#[test]
fn recycle_accepts_the_target_listed_before_the_predecessor() {
    let t = 1_000_000;
    let (mut ins, outs) = recycle_inputs(t, abs_ts(t + 30 * 86_400));
    ins.swap(0, 1);
    let res = verify(&ins, &outs, b"recycle", &[], false);
    assert!(res.is_ok(), "recycle must not depend on input order, got {res:?}");
}

/// The register half of R-1, reached for real. In the v3 layout the id is derived
/// from the label, so "id zero with label old" cannot be written at all and
/// `register_must_not_forge_a_name_at_the_root_id` now fails on the predecessor
/// range (24), never touching the root guard. The only cell whose id is zero is the
/// EMPTY label, which the integrity loop exempts from the charset rule; into a
/// self-looping ring `between` admits it, and without the guard the fee schedule
/// (u64::MAX at length zero) is what stops it. Two guards, and this pins the first.
#[test]
fn register_refuses_the_empty_label_even_where_the_ring_admits_id_zero() {
    let old = account_id(b"old");
    let (p_before, _) = account_cell(old, old, FUTURE, b"old", &records_witness());
    let (p_after, p_after_w) = account_cell(old, ROOT_ID, FUTURE, b"old", &records_witness());
    let (root2, root2_w) = account_cell(ROOT_ID, old, FUTURE, b"", &WitnessData::default());
    let outs = vec![
        outc(&p_after, &p_after_w),
        OutC { cap: ALICE_PRICE, ..outc(&root2, &root2_w) },
        treasury_out(FEE_1Y),
    ];
    let res = verify_full(&[inc(&p_before)], &outs, b"register", &[], false, Some(&Commit::good()));
    assert_code(&res, 46, "a second sentinel minted into a ring that covers id zero");
}

/// What `register_must_not_forge_a_name_at_the_root_id` actually exercises today: the
/// same shape, with the reason pinned. The label "old" derives id `old`, so the
/// "forged id zero" that test describes is unexpressible and the transaction dies on
/// the predecessor range, one check before the root guard. Its `is_err()` would stay
/// green with `RootNotRecyclable` deleted from `validate_register`.
#[test]
fn the_v3_layout_cannot_express_the_r1_forgery_at_all() {
    let old = account_id(b"old");
    let (p_before, _) = account_cell(old, old, FUTURE, b"old", &records_witness());
    let (p_after, p_after_w) = account_cell(old, ROOT_ID, FUTURE, b"old", &records_witness());
    let (forged, forged_w) = account_cell(ROOT_ID, old, FUTURE, b"old", &records_witness());
    let outs = vec![
        outc(&p_after, &p_after_w),
        OutC { cap: 1_000 * 100_000_000, owner: L::B, ..outc(&forged, &forged_w) },
        treasury_out(80_000 * 100_000_000),
    ];
    let res = verify_full(&[inc(&p_before)], &outs, b"register", &[], false, Some(&Commit::good()));
    assert_code(&res, 24, "a duplicate label is a range failure, not a root-guard failure");
}

#[test]
fn an_output_carrying_a_future_version_byte_is_refused() {
    // A version this contract does not know is not accepted on faith: the byte is
    // what lets the next layout be an upgrade, and it only works if unknown values
    // are refused rather than parsed as whatever this build expects.
    let (d, w) = account_cell(account_id(b"alice"), ROOT_ID, FUTURE, b"alice", &records_witness());
    let res = verify(&[inc(&d)], &[outc(&with_version(&d, 0x04), &w)], b"edit_records", &[L::A], false);
    assert_code(&res, 20, "a version this contract does not know");
}

// --- properties, not examples ------------------------------------------------------
//
// Everything above this line is a case: a transaction somebody imagined, asserted to
// behave. F-8 (SECURITY.md) went through 171 of those and eight review passes without
// being seen, because none of them asked the question an attacker asks, which is not
// "does this behave?" but "is there **any** transaction in this space that does not?".
//
// These sweep a grid instead. The space is small enough to enumerate exactly, so nothing
// is random and nothing needs a seed. Each one states an **if and only if**: the contract
// accepts exactly when the rule says it should. The "only if" half is what the cases
// already covered; the "if" half, the direction that lets something through, is the half
// that was missing and is where F-8 lived.

/// Capacities to try around whatever a cell holds: short by a shannon, exact, and
/// generous. A shannon is the interesting one, because an off-by-one in a comparison
/// fails open and looks like nothing.
const DELTAS: [i64; 5] = [-(100 * 100_000_000), -1, 0, 1, 100 * 100_000_000];

fn shift(base: u64, d: i64) -> u64 {
    (base as i64 + d).max(0) as u64
}

/// Every action that keeps a name in place must not let the cell shrink: the capacity
/// is the owner's refundable deposit, and three of these are permissionless, so a
/// stranger could otherwise keep the name intact and walk off with a slice of the rent.
#[test]
fn property_no_action_may_shrink_the_name_cell() {
    let id = account_id(b"alice");
    let w = records_witness();
    let mut wrong = Vec::new();
    let mut checked = 0;

    for d in DELTAS {
        let cap = shift(CAP, d);
        let should = cap >= CAP;

        // renew: the fee is paid in full, so only the capacity is in question.
        let (din, _) = account_cell(id, ROOT_ID, FUTURE, b"alice", &w);
        let (dout, pout) = account_cell(id, ROOT_ID, FUTURE + ONE_YEAR, b"alice", &w);
        let outs = [OutC { cap, ..outc(&dout, &pout) }, treasury_out(FEE_1Y)];
        let did = verify(&[inc(&din)], &outs, b"renew", &[], false).is_ok();
        checked += 1;
        if did != should {
            wrong.push(format!("renew at {cap}: contract {did}, rule {should}"));
        }

        // edit_records: the owner signs, the records change, the capacity must not.
        let w2 = WitnessData {
            records: vec![RecordEntry {
                key: b"address.309".to_vec(),
                label: b"".to_vec(),
                value: b"ckt1qskimmed".to_vec(),
                ttl: 300,
            }],
        };
        let (ein, _) = account_cell(id, ROOT_ID, FUTURE, b"alice", &w);
        let (eout, epout) = account_cell(id, ROOT_ID, FUTURE, b"alice", &w2);
        let did = verify(&[inc(&ein)], &[OutC { cap, ..outc(&eout, &epout) }], b"edit_records", &[L::A], false).is_ok();
        checked += 1;
        if did != should {
            wrong.push(format!("edit_records at {cap}: contract {did}, rule {should}"));
        }

        // transfer: the owner changes, and with it the manager. Nothing else may.
        let (tin, _) = account_cell(id, ROOT_ID, FUTURE, b"alice", &w);
        let (tout, tpout) = account_cell(id, ROOT_ID, FUTURE, b"alice", &w);
        let out = OutC { cap, owner: L::B, manager: Some(L::B), ..outc(&tout, &tpout) };
        let did = verify(&[inc(&tin)], &[out], b"transfer", &[L::A], false).is_ok();
        checked += 1;
        if did != should {
            wrong.push(format!("transfer at {cap}: contract {did}, rule {should}"));
        }
    }

    assert!(wrong.is_empty(), "{} of {checked} disagree:\n  {}", wrong.len(), wrong.join("\n  "));
    assert!(checked >= 15, "only {checked} combinations; the grid has shrunk");
}

/// `recycle` splices an expired name out of the list. The name beside it is an innocent
/// third party whose deposit must survive untouched, and the action is permissionless,
/// so whoever runs it is not the person who would notice.
#[test]
fn property_recycle_never_touches_the_neighbour() {
    let t = 1_000_000;
    let mut wrong = Vec::new();
    for d in DELTAS {
        // Past expiry AND past the grace period, which is the ordinary case: a since
        // that only clears expiry is refused for a different reason and would make every
        // row of this sweep read the same.
        let (ins, mut outs) = recycle_inputs(t, abs_ts(t + 30 * 86_400));
        outs[0].cap = shift(CAP, d);
        let should = outs[0].cap >= CAP;
        let did = verify(&ins, &outs, b"recycle", &[], false).is_ok();
        if did != should {
            wrong.push(format!("recycle with the neighbour at {}: contract {did}, rule {should}", outs[0].cap));
        }
    }
    assert!(wrong.is_empty(), "{}", wrong.join("\n  "));
}

/// The fee, swept the same way. It is the whole of the protocol's revenue on a
/// registration and a renewal, and both actions are permissionless: nobody who would
/// mind is required to be present, so the only thing standing between the treasury and
/// a short payment is this comparison.
#[test]
fn property_the_fee_must_be_paid_in_full_or_not_at_all() {
    let id = account_id(b"alice");
    let w = records_witness();
    let mut wrong = Vec::new();
    let mut refused = 0;

    for d in DELTAS {
        let paid = shift(FEE_1Y, d);
        let should = paid >= FEE_1Y;

        let (din, _) = account_cell(id, ROOT_ID, FUTURE, b"alice", &w);
        let (dout, pout) = account_cell(id, ROOT_ID, FUTURE + ONE_YEAR, b"alice", &w);
        let did = verify(&[inc(&din)], &[outc(&dout, &pout), treasury_out(paid)], b"renew", &[], false).is_ok();
        if !did {
            refused += 1;
        }
        if did != should {
            wrong.push(format!("renew paying {paid} of {FEE_1Y}: contract {did}, rule {should}"));
        }

        let (rin, mut routs) = register_fixture();
        let last = routs.len() - 1;
        routs[last].cap = paid;
        // A register needs its matured commitment, or it is refused for a reason that
        // has nothing to do with the fee and every row reads the same.
        let did = verify_full(&[rin], &routs, b"register", &[], false, Some(&Commit::good())).is_ok();
        if did != should {
            wrong.push(format!("register paying {paid} of {FEE_1Y}: contract {did}, rule {should}"));
        }
    }

    assert!(wrong.is_empty(), "{}", wrong.join("\n  "));
    // The control on the sweep: a grid that never saw a refusal would pass against a
    // contract that asks for no fee at all.
    assert!(refused >= 2, "the sweep never exercised a short payment, so it proves nothing");
}

// --- the four families that still had only examples --------------------------------
//
// Added 2026-09-14, after capacity and the fee. Each is the same shape: enumerate a grid,
// assert an if-and-only-if, and then break the guard and watch the property fail, which is
// the step that makes it worth having and the one that is easy to skip.

/// The id is NOT a field, which is a stronger guarantee than a check.
///
/// A property was written here on 2026-09-14 asserting that a cell's id must equal its
/// label's hash, and it failed in both directions, which is almost always the fixture
/// rather than the contract. It was: **there is no stored id** (decision 0015). The id is
/// derived from the label every time it is needed, so there is no field to forge and the
/// rule cannot be broken by any transaction. A test for it would test the test.
///
/// What does need checking is the arithmetic that decides where a derived id may be
/// spliced in, and that is at the foot of this file.

/// A registration splices a name into the ring, and every other name must come out of it
/// untouched.
///
/// The predecessor is the only cell besides the new one the transaction may carry, and
/// only its next pointer may move. Everything else about it, owner, manager, lock,
/// capacity, belongs to somebody who is not in the room: register is permissionless, so
/// the person whose cell is being edited is not required to be present or to agree.
#[test]
fn property_a_registration_leaves_every_other_name_alone() {
    let cases: [(&str, fn(&mut OutC)); 5] = [
        ("nothing", |_o: &mut OutC| {}),
        ("the predecessor's owner", |o: &mut OutC| o.owner = L::B),
        ("the predecessor's manager", |o: &mut OutC| o.manager = Some(L::B)),
        ("the predecessor's lock", |o: &mut OutC| o.lock = L::A),
        ("the predecessor's capacity", |o: &mut OutC| o.cap = CAP - 1),
    ];
    let mut wrong = Vec::new();
    for (what, mutate) in cases {
        let (i, mut o) = register_fixture();
        mutate(&mut o[0]);
        let honest = what == "nothing";
        let did = verify_full(&[i], &o, b"register", &[], false, Some(&Commit::good())).is_ok();
        if did != honest {
            wrong.push(format!("register changing {what}: contract {did}, rule {honest}"));
        }
    }
    assert!(wrong.is_empty(), "{}", wrong.join("\n  "));
}

/// The commitment must be old enough, must be the right kind of old, and must belong to
/// the person registering.
///
/// Commit-reveal is the whole of the front-running defence: without it a name typed into a
/// mempool is a name somebody else can have. The three ways it fails are a young
/// commitment, an absolute since (which consensus does not enforce as a delay at all), and
/// a commitment held by somebody else, which looked fine for a long time because every
/// fixture used one wallet for both holder and owner.
#[test]
fn property_a_commitment_must_be_matured_relative_and_the_registrants_own() {
    let mut wrong = Vec::new();
    let mut refused = 0;

    for secs in [0u64, COMMIT_MIN_DELAY - 1, COMMIT_MIN_DELAY, COMMIT_MIN_DELAY + 600] {
        for relative in [true, false] {
            for holder in [L::A, L::B] {
                let honest = relative && secs >= COMMIT_MIN_DELAY && matches!(holder, L::A);
                let c = Commit {
                    since: if relative { rel_ts(secs) } else { abs_ts(secs) },
                    holder,
                    ..Commit::good()
                };
                let (i, o) = register_fixture();
                let did = verify_full(&[i], &o, b"register", &[], false, Some(&c)).is_ok();
                if !did {
                    refused += 1;
                }
                if did != honest {
                    wrong.push(format!(
                        "commit {secs}s {} held by {}: contract {did}, rule {honest}",
                        if relative { "relative" } else { "absolute" },
                        if matches!(holder, L::A) { "the owner" } else { "a stranger" }
                    ));
                }
            }
        }
    }
    // And a commitment whose bytes do not match at all, whatever its age.
    let bad = Commit { bad_data: Some(Bytes::from_static(&[0x11; 32])), ..Commit::good() };
    let (i, o) = register_fixture();
    if verify_full(&[i], &o, b"register", &[], false, Some(&bad)).is_ok() {
        wrong.push("a commitment whose bytes do not match was accepted".to_string());
    }

    assert!(wrong.is_empty(), "{}", wrong.join("\n  "));
    assert!(refused >= 10, "the sweep never saw a bad commitment refused");
}

/// A name may only be recycled once it has expired and outlived the grace period, and only
/// with a since the chain itself will enforce.
///
/// The proof of expiry is a since the attacker writes, so the contract must refuse every
/// shape of it that does not actually bind. Recycling early takes a live name from its
/// owner, which is the worst outcome anywhere in this file.
#[test]
fn property_a_name_cannot_be_recycled_before_its_grace_period_ends() {
    const GRACE: u64 = 30 * 86_400;
    let expiry = 1_000_000u64;
    let mut wrong = Vec::new();
    let mut refused = 0;

    for offset in [-(GRACE as i64), -1i64, 0, GRACE as i64 - 1, GRACE as i64, GRACE as i64 + 86_400] {
        for absolute in [true, false] {
            let t = (expiry as i64 + offset).max(0) as u64;
            // Only an absolute timestamp at or past expiry plus grace binds: a relative
            // since is counted from the input's own block and proves nothing about when
            // the name expired.
            let honest = absolute && t >= expiry + GRACE;
            let since = if absolute { abs_ts(t) } else { rel_ts(t) };
            let (ins, outs) = recycle_inputs(expiry, since);
            let did = verify(&ins, &outs, b"recycle", &[], false).is_ok();
            if !did {
                refused += 1;
            }
            if did != honest {
                wrong.push(format!(
                    "recycle at {t} ({}): contract {did}, rule {honest}",
                    if absolute { "absolute" } else { "relative" }
                ));
            }
        }
    }
    assert!(wrong.is_empty(), "{}", wrong.join("\n  "));
    assert!(refused >= 6, "the sweep never saw an early recycle refused");
}

/// The ring arithmetic, exhaustively, on a ring small enough to enumerate.
///
/// `between` and `covers` decide where a name may be spliced in and which predecessor may
/// answer for an id. Everything about the uniqueness of a name rests on them: get the
/// wraparound wrong and two cells can hold the same label, or a registration can be
/// inserted where it does not belong. The pass-6 review named this arithmetic as the one
/// area it did not check, and it stayed unchecked until now.
///
/// The ids are 20 bytes, so the real space cannot be enumerated. This maps a one-byte ring
/// onto it, putting the varying byte first so ordering is preserved (`Id` compares
/// lexicographically, big-endian in effect), and then checks every one of the 256x256x256
/// combinations against the definition written out independently. Sixteen million cases,
/// about a second, and no wraparound case can be the one nobody thought of.
#[test]
fn property_the_ring_arithmetic_agrees_with_its_own_definition() {
    fn id_of(b: u8) -> Id {
        let mut id = [0u8; 20];
        id[0] = b;
        id
    }

    let mut bad_between = 0u32;
    let mut bad_covers = 0u32;
    let mut first = String::new();
    let mut seen_wrap = 0u32;

    for lo in 0u16..=255 {
        for hi in 0u16..=255 {
            let (l, h) = (lo as u8, hi as u8);
            if l >= h {
                seen_wrap += 1;
            }
            for x in 0u16..=255 {
                let i = x as u8;
                // The definitions, written out again rather than reused: walking forward
                // from `lo` you reach `id` before you reach `hi`. Open for `between`, so
                // neither endpoint counts; half-open for `covers`, so `hi` does.
                // Distance walking forward around the ring, where arriving back where you
                // started is a **full lap** and not zero steps. That is the whole of the
                // degenerate case: a ring of one name points at itself, so its range is
                // everything, and the first draft of this definition called that an empty
                // range and reported sixty-five thousand disagreements with a contract
                // that was right. The independent definition was the thing that was wrong,
                // which is what an independent definition is for.
                let steps = |from: u8, to: u8| {
                    let d = (to as u16 + 256 - from as u16) % 256;
                    if d == 0 { 256 } else { d }
                };
                let span = steps(l, h);
                let dist = steps(l, i);
                let want_between = i != h && dist < span;
                let want_covers = dist <= span;

                let got_between = between(&id_of(l), &id_of(h), &id_of(i));
                let got_covers = covers(&id_of(l), &id_of(h), &id_of(i));

                if got_between != want_between {
                    bad_between += 1;
                    if first.is_empty() {
                        first = format!("between({l}, {h}, {i}) said {got_between}, the definition says {want_between}");
                    }
                }
                if got_covers != want_covers {
                    bad_covers += 1;
                    if first.is_empty() {
                        first = format!("covers({l}, {h}, {i}) said {got_covers}, the definition says {want_covers}");
                    }
                }
            }
        }
    }

    assert_eq!(
        (bad_between, bad_covers),
        (0, 0),
        "{bad_between} disagreements on between and {bad_covers} on covers. First: {first}"
    );
    // The control: a sweep that never crossed the wraparound would agree with any
    // implementation that handles only the ordered case.
    assert!(seen_wrap > 30_000, "only {seen_wrap} wrapped ranges; the sweep is not exercising the hard half");
}

/// A name cannot be spliced in where it does not belong, and the endpoints are not "in".
///
/// The same rule at the level that matters: `between` is what stops a second cell claiming
/// a range that is already somebody's, and an off-by-one at either endpoint is a duplicate
/// name rather than a rounding error.
#[test]
fn property_a_range_never_admits_its_own_endpoints() {
    fn id_of(b: u8) -> Id {
        let mut id = [0u8; 20];
        id[0] = b;
        id
    }
    for lo in 0u16..=255 {
        for hi in 0u16..=255 {
            let (l, h) = (lo as u8, hi as u8);
            assert!(!between(&id_of(l), &id_of(h), &id_of(l)), "between admitted its own low endpoint at ({l}, {h})");
            assert!(!between(&id_of(l), &id_of(h), &id_of(h)), "between admitted its own high endpoint at ({l}, {h})");
            // `covers` is half-open, so the high endpoint is inside and the low one is not.
            // Except when they are the same name: a ring of one points at itself, its range
            // is the whole ring, and it covers itself. That case is the root before anybody
            // has registered anything, and it has to be true or nothing can ever be added.
            if l != h {
                assert!(!covers(&id_of(l), &id_of(h), &id_of(l)), "covers admitted its low endpoint at ({l}, {h})");
            } else {
                assert!(covers(&id_of(l), &id_of(h), &id_of(l)), "a ring of one must cover itself at ({l})");
            }
        }
    }
}

/// What these scripts cost as a transaction grows, which nobody had measured.
///
/// Every validator here walks lists it does not bound: `require_treasury` reads every
/// output, `owed_over_offers` reads every input, `price_factor` and `require_parent` read
/// every cell dep. The harness has always run two or three cells, so the shape of the cost
/// curve was unknown, and two questions follow from not knowing it. **Does an honest
/// transaction ever become impossible** because a wallet with many change cells pushes the
/// script past what a block allows? And **is there a grief**: can a stranger make somebody
/// else's transaction expensive by adding cells to it?
///
/// The numbers are printed, not asserted against a magic figure. What is asserted is the
/// shape: that the cost grows at most linearly with the number of cells, and that at a
/// transaction far larger than anything a wallet builds it is still a small fraction of a
/// block. A quadratic here would be the finding.
#[test]
fn property_the_cost_grows_at_most_linearly_with_the_transaction() {
    let id = account_id(b"alice");
    let w = records_witness();
    let mut measured = Vec::new();

    for extra in [0usize, 4, 16, 64, 128] {
        let (din, _) = account_cell(id, ROOT_ID, FUTURE, b"alice", &w);
        let (dout, pout) = account_cell(id, ROOT_ID, FUTURE + ONE_YEAR, b"alice", &w);
        // The account cell, the fee, and then `extra` ordinary outputs, which is what a
        // wallet's change looks like and what a stranger could pad a transaction with.
        let mut outs = vec![outc(&dout, &pout), treasury_out(FEE_1Y)];
        for _ in 0..extra {
            outs.push(plain_out(L::B, 100 * 100_000_000));
        }
        let cycles = verify(&[inc(&din)], &outs, b"renew", &[], false)
            .unwrap_or_else(|e| panic!("a renew with {extra} extra outputs must still be valid: {e}"));
        measured.push((extra, cycles));
    }

    for (n, c) in &measured {
        println!("renew with {n} extra outputs: {c} cycles");
    }

    let base = measured[0].1;
    let (biggest_n, biggest) = *measured.last().unwrap();
    let per_cell = (biggest - base) / biggest_n as u64;
    println!("base {base} cycles, {per_cell} per extra output");

    // Linear, not quadratic: doubling the cells must not quadruple the cost. Checked
    // between the last two points, where a quadratic would be unmistakable.
    let (n1, c1) = measured[measured.len() - 2];
    let growth = (biggest - base) as f64 / (c1 - base).max(1) as f64;
    let ratio = biggest_n as f64 / n1 as f64;
    assert!(
        growth <= ratio * 1.5,
        "cost grew {growth:.1}x while the transaction grew {ratio:.1}x, which is not linear"
    );

    // And the absolute figure, against the only number that matters: a CKB block allows
    // 3.5 billion cycles in total. A script that cannot fit a large honest transaction
    // into a fraction of that is a script with a size limit nobody wrote down.
    const BLOCK_LIMIT: u64 = 3_500_000_000;
    assert!(
        biggest < BLOCK_LIMIT / 100,
        "a transaction with {biggest_n} extra outputs costs {biggest} cycles, over a hundredth of a block"
    );
}

/// The same question for the inputs side, where the sale lock walks every one.
#[test]
fn property_extra_inputs_do_not_make_a_renew_expensive() {
    let id = account_id(b"alice");
    let w = records_witness();
    let mut measured = Vec::new();

    for extra in [0usize, 8, 32, 96] {
        let (din, _) = account_cell(id, ROOT_ID, FUTURE, b"alice", &w);
        let (dout, pout) = account_cell(id, ROOT_ID, FUTURE + ONE_YEAR, b"alice", &w);
        let padding: Vec<L> = core::iter::repeat(L::B).take(extra).collect();
        let cycles = verify(&[inc(&din)], &[outc(&dout, &pout), treasury_out(FEE_1Y)], b"renew", &padding, false)
            .unwrap_or_else(|e| panic!("a renew with {extra} extra inputs must still be valid: {e}"));
        measured.push((extra, cycles));
    }
    for (n, c) in &measured {
        println!("renew with {n} extra inputs: {c} cycles");
    }
    let base = measured[0].1;
    let (biggest_n, biggest) = *measured.last().unwrap();
    println!("base {base}, {} per extra input", (biggest.saturating_sub(base)) / biggest_n.max(1) as u64);
    assert!(biggest < 3_500_000_000 / 100, "{biggest} cycles is over a hundredth of a block");
}
