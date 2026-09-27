//! Owner consent that arrives through a second lock. From the contracts review of
//! 2026-09-27, run against the contracts after the upgrade that refuses anyone-can-pay
//! owners (`owner_consent.rs`).
//!
//! **A deed.** A name held as a deed is owned by `input-type-proxy-lock` over a Spore
//! (decision 0036). That lock opens for any transaction with the Spore among its inputs,
//! and `account-cell-type` takes an input under it as the owner's consent. Nothing asks how
//! the Spore got into the inputs. Under an anyone-can-pay lock a stranger can spend the
//! holder's Spore by handing it back topped up, so `speaks_for_owner` looks one lock too
//! shallow for a deed: the holder's lock is the one that decides, and it is never checked.
//!
//! **A listing.** A name listed for sale is owned by the sale lock, which opens for whoever
//! pays the price. `account-cell-type` takes that input as consent to any owner action,
//! not only the transfer the price was asked for.
//!
//! Two real binaries are used, read from mainnet on 2026-09-27 and checked by hash below:
//! `input-type-proxy-lock` (code cell `0x10d63a99…:1`) and Omnilock (code cell
//! `0xc76edf46…:0`, recreated here under its own type id args).
use ckb_testtool::builtin::ALWAYS_SUCCESS;
use ckb_testtool::ckb_crypto::secp::Privkey;
use ckb_testtool::ckb_hash::{blake2b_256, new_blake2b};
use ckb_testtool::ckb_types::{
    bytes::Bytes,
    core::{HeaderBuilder, ScriptHashType, TransactionBuilder, TransactionView},
    packed,
    packed::{CellDep, CellInput, CellOutput, OutPoint, Script, WitnessArgs},
    prelude::*,
    H256,
};
use ckb_testtool::context::Context;
use cells_core::{
    account_id, build_account_data, ckb_blake2b256, commitment, lets_anyone_spend, registration_fee, sale_fee,
    ANYONE_CAN_PAY_CODE_HASHES, COMMIT_MIN_DELAY, NAMESPACE_LEN, OMNILOCK_ANYONE_CAN_PAY, OMNILOCK_CODE_HASHES,
    OWNER_HASH_LEN, ROOT_ID, SECRET_LEN,
};

const MAX_CYCLES: u64 = 200_000_000;
const CKB: u64 = 100_000_000;
const HEADER_TS_MS: u64 = 1_700_000_000_000;
const NOW: u64 = HEADER_TS_MS / 1000;
const ONE_YEAR: u64 = 365 * 86_400;
const NAME_CAP: u64 = 300 * CKB;
const FUNDS: u64 = 100_000 * CKB;
const TX_FEE: u64 = 1_000;
/// What the stranger adds to the holder's cell: the anyone-can-pay condition.
const TOP_UP: u64 = CKB;
/// A deed's proxy cell (sdk/src/deed.ts writes 60 bytes of data), a meal, and the Spore.
const PROXY_CAP: u64 = 133 * CKB;
const MEAL_CAP: u64 = 73 * CKB;
const SPORE_CAP: u64 = 322 * CKB;
const PRICE: u64 = 10_000 * CKB;
const OFFER_CAP: u64 = 100 * CKB;
const TO_SELLER: u64 = PRICE - sale_fee(PRICE) + OFFER_CAP;
const HOLDER: u8 = 0x0C;
const SELLER: u8 = 0x0D;

/// `input-type-proxy-lock`, `data1`, the code hash every deed names (decision 0036).
const PROXY_CODE_HASH: &str = "5123908965c711b0ffd8aec642f1ede329649bda1ebdca6bd24124d3796f768a";
/// The contracts live on mainnet today, read from chain on 2026-09-27 (dep outpoints
/// `0xe9122f59…:0` and `0x192db7b6…:0`), and the sale lock's code cell's type id args.
const MAINNET_ACCOUNT_DATA_HASH: &str = "f86bdba9ff22b5018dcb90a22cdb3720cd5ea8868ab94959ac8146a6789aae30";
const MAINNET_SALE_DATA_HASH: &str = "f1160f64a82e3509211b2903fc54f9f15cbdc4758d058f107608d30727072a93";
const MAINNET_SALE_TYPE_ID_ARGS: &str = "05238ca98c4bc67cb6592707ba40301141344b53687f73d73f702f0cc2d7985f";
const MAINNET_SALE_CODE_HASH: &str = "086c8f4e9d4272e3dfbaca399792f730e6604591e87931ee6d67047a3c900879";
/// The mainnet treasury: secp256k1_blake160 by type id, these args, this lock hash.
const SECP256K1_CODE_HASH: &str = "9bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce8";
const MAINNET_TREASURY_ARGS: [u8; 20] = [
    0xe1, 0xf6, 0x01, 0xa9, 0x0f, 0x38, 0xdc, 0x2b, 0x55, 0x1e, 0xe9, 0x7a, 0x2f, 0x3d, 0x83, 0x87, 0x6b, 0x2e, 0x67, 0x07,
];
const MAINNET_TREASURY_LOCK_HASH: &str = "57d926a44d83fc13b21ce037b1e31f4223e3c867cfa3f60e1324d5bfd5cd742d";
/// Omnilock's mainnet code cell: its type id args, and the data hash of what it held.
const OMNILOCK_TYPE_ID_ARGS: &str = "855508fe0f0ca25b935b070452ecaee48f6c9f1d66cd15f046616b99e948236a";
const OMNILOCK_DATA_HASH: &str = "768f306681da232ceb0b94f436c5f813377179762a831c5ad8797bd4fd2d118d";

fn h32(s: &str) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (i, o) in out.iter_mut().enumerate() {
        *o = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).expect("hex");
    }
    out
}

/// A contract from the test build `make test` makes (`target/test-treasury`), the only
/// build compiled with the harness's treasury and sale lock. `CELLS_CONTRACTS_DIR` wins
/// when set, as for the other files; without it the shared `Loader` looks in the plain
/// release directory, which holds only `price-cell-type`, so a bare `cargo test` of this
/// file failed every test that deploys a contract.
fn contract(name: &str) -> Bytes {
    let dir = std::env::var("CELLS_CONTRACTS_DIR").unwrap_or_else(|_| {
        format!("{}/../target/test-treasury/riscv64imac-unknown-none-elf/release", env!("CARGO_MANIFEST_DIR"))
    });
    let path = format!("{dir}/{name}");
    Bytes::from(std::fs::read(&path).unwrap_or_else(|e| {
        panic!("read {path}: {e}\nbuild the test contracts first: `make test` from contracts/")
    }))
}

fn fixture(name: &str) -> Bytes {
    let path = format!("{}/fixtures/{name}", env!("CARGO_MANIFEST_DIR"));
    Bytes::from(std::fs::read(&path).unwrap_or_else(|e| panic!("read {path}: {e}")))
}

fn assert_code(res: &Result<u64, String>, code: i32, what: &str) {
    let e = res.as_ref().err().unwrap_or_else(|| panic!("{what}: expected a failure, it passed"));
    assert!(e.contains(&format!("error code {code} ")), "{what}: wanted error {code}, got {e}");
}

fn show(what: &str, res: &Result<u64, String>) {
    match res {
        Ok(c) => println!("{what}: ACCEPTED ({c} cycles)"),
        Err(e) => {
            let short = e.split(" on page").next().unwrap_or(e);
            println!("{what}: REJECTED {short}");
        }
    }
}

// --- the locks ------------------------------------------------------------------------

/// The anyone-can-pay family as `lets_anyone_spend` lists it, by type id args on chain.
/// As in `owner_consent.rs`, each code cell is recreated under its real type id with
/// always-success in it, which is what the real lock allows a stranger who tops it up.
#[derive(Clone, Copy, Debug)]
enum Listed {
    AnyoneCanPayMainnet,
    AnyoneCanPayTestnet,
    PwLockMainnet,
    PwLockTestnet,
    OmnilockAcpMainnet,
    OmnilockAcpTestnet,
}

const LISTED: [Listed; 6] = [
    Listed::AnyoneCanPayMainnet,
    Listed::AnyoneCanPayTestnet,
    Listed::PwLockMainnet,
    Listed::PwLockTestnet,
    Listed::OmnilockAcpMainnet,
    Listed::OmnilockAcpTestnet,
];

impl Listed {
    fn type_id_args(self) -> [u8; 32] {
        h32(match self {
            Listed::AnyoneCanPayMainnet => "de8b879bd1e98399de0dc9be163e703fc1fb82d9379ee1e85143b9f5a863610c",
            Listed::AnyoneCanPayTestnet => "b9c8cb04f45fc2ad69cc37c14a70e601a4236369b9cb0bb1fff1e386d5ffde46",
            Listed::PwLockMainnet => "42ade2f25eb938b5dbfd3d8f07b8b07aa593d848e7ff14bdfbbea5aeb6175261",
            Listed::PwLockTestnet => "f6d90bfe3041d0fd7e01c45770241697f5f837974bd6ae1672a7ec0f9f523268",
            Listed::OmnilockAcpMainnet => OMNILOCK_TYPE_ID_ARGS,
            Listed::OmnilockAcpTestnet => "761f51fc9cd6a504c32c6ae64b3746594d1af27629b427c5ccf6c9a725a89144",
        })
    }

    fn args(self, key: u8) -> Bytes {
        match self {
            Listed::OmnilockAcpMainnet | Listed::OmnilockAcpTestnet => omnilock_args(key, OMNILOCK_ANYONE_CAN_PAY),
            _ => Bytes::from(vec![key; 20]),
        }
    }
}

/// Omnilock args: auth flag 0 (a CKB secp256k1 key), the 20-byte id, the flags byte, and
/// the two minimums the anyone-can-pay flag requires (0, so a top-up of one shannon does).
fn omnilock_args(key: u8, flags: u8) -> Bytes {
    let mut a = vec![0x00];
    a.extend_from_slice(&[key; 20]);
    a.push(flags);
    if flags & OMNILOCK_ANYONE_CAN_PAY != 0 {
        a.extend_from_slice(&[0, 0]);
    }
    Bytes::from(a)
}

/// The lock a deed's Spore sits under.
#[derive(Clone, Copy, Debug)]
enum Holder {
    /// A lock on the list, modelled as above.
    Listed(Listed),
    /// The real Omnilock binary, in anyone-can-pay mode or not.
    Omnilock { acp: bool },
    /// secp256k1_blake160_sighash_all, nobody signs.
    SecpUnsigned,
    /// The same, signed by its key.
    SecpSigned,
}

/// Which contracts a transaction runs against.
#[derive(Clone, Copy, PartialEq, Debug)]
enum Build {
    /// The test build of this checkout (`make test`).
    Test,
    /// The binaries live on mainnet today, checked by data hash, with the sale lock under
    /// its mainnet type id and the fee paid to the mainnet treasury lock. They predate the
    /// 2026-09-27 upgrade.
    Mainnet,
}

struct Env {
    ctx: Context,
    acct_type: Script,
    acct_lock: Script,
    plain_op: OutPoint,
    sale_op: OutPoint,
    proxy_op: OutPoint,
    stranger: Script,
    treasury: Script,
    ns: [u8; NAMESPACE_LEN],
}

fn env() -> Env {
    env_for(Build::Test)
}

fn env_for(build: Build) -> Env {
    let mut ctx = Context::default();
    let (acct_bin, sale_bin, sale_args) = match build {
        Build::Test => (contract("account-cell-type"), contract("sale-lock"), tests::SALE_TYPE_ID_ARGS),
        Build::Mainnet => {
            let (a, s) = (fixture("account-cell-type-mainnet"), fixture("sale-lock-mainnet"));
            assert_eq!(ckb_blake2b256(&a), h32(MAINNET_ACCOUNT_DATA_HASH), "not the mainnet account-cell-type");
            assert_eq!(ckb_blake2b256(&s), h32(MAINNET_SALE_DATA_HASH), "not the mainnet sale-lock");
            (a, s, h32(MAINNET_SALE_TYPE_ID_ARGS))
        }
    };
    let acct_op = ctx.deploy_cell(acct_bin);
    let sale_op = tests::deploy_under_type_id(&mut ctx, sale_args, sale_bin);
    if build == Build::Mainnet {
        assert_eq!(tests::type_id_hash(sale_args), h32(MAINNET_SALE_CODE_HASH), "the mainnet sale lock's type id");
    }
    let proxy_op = ctx.deploy_cell(fixture("input-type-proxy-lock"));
    // Before any lock is recreated from always-success: `deploy_cell` hands back whichever
    // cell was registered last under a binary's data hash.
    let plain_op = ctx.deploy_cell(ALWAYS_SUCCESS.clone());
    let token = ctx.build_script(&plain_op, Bytes::from_static(b"genesis-token")).expect("token");
    let mut ns = [0u8; NAMESPACE_LEN];
    ns.copy_from_slice(&token.calc_script_hash().as_bytes()[..NAMESPACE_LEN]);
    let acct_type = ctx.build_script(&acct_op, Bytes::from(ns.to_vec())).expect("acct type");
    let acct_lock = ctx.build_script(&plain_op, Bytes::from_static(b"cells-account-lock")).expect("acct lock");
    let stranger = ctx.build_script(&plain_op, Bytes::from_static(b"stranger")).expect("stranger");
    let treasury = match build {
        Build::Test => ctx
            .build_script_with_hash_type(&plain_op, ScriptHashType::Data1, Bytes::from_static(b"treasury"))
            .expect("treasury"),
        // Only ever an output here, so no code cell is needed for it.
        Build::Mainnet => {
            let t = Script::new_builder()
                .code_hash(h32(SECP256K1_CODE_HASH).pack())
                .hash_type(ScriptHashType::Type.into())
                .args(Bytes::from(MAINNET_TREASURY_ARGS.to_vec()).pack())
                .build();
            assert_eq!(t.calc_script_hash().as_slice(), &h32(MAINNET_TREASURY_LOCK_HASH)[..], "the mainnet treasury");
            t
        }
    };
    Env { ctx, acct_type, acct_lock, plain_op, sale_op, proxy_op, stranger, treasury, ns }
}

fn system_script(name: &str) -> Bytes {
    let bin = ckb_system_scripts::BUNDLED_CELL.get(&format!("specs/cells/{name}")).expect("bundled system script");
    Bytes::from(bin.to_vec())
}

fn holder_lock(e: &mut Env, who: Holder) -> (Script, Option<Privkey>, Vec<CellDep>) {
    match who {
        Holder::Listed(l) => {
            let op = tests::deploy_under_type_id(&mut e.ctx, l.type_id_args(), ALWAYS_SUCCESS.clone());
            (e.ctx.build_script(&op, l.args(HOLDER)).expect("listed lock"), None, vec![])
        }
        Holder::Omnilock { acp } => {
            let code = fixture("omnilock-mainnet");
            assert_eq!(ckb_blake2b256(&code), h32(OMNILOCK_DATA_HASH), "the fixture is not the Omnilock read from mainnet");
            let op = tests::deploy_under_type_id(&mut e.ctx, h32(OMNILOCK_TYPE_ID_ARGS), code);
            let flags = if acp { OMNILOCK_ANYONE_CAN_PAY } else { 0 };
            let lock = e.ctx.build_script(&op, omnilock_args(HOLDER, flags)).expect("omnilock");
            assert_eq!(lock.code_hash().as_slice(), &OMNILOCK_CODE_HASHES[0][..], "Omnilock's mainnet type id");
            (lock, None, vec![])
        }
        Holder::SecpUnsigned | Holder::SecpSigned => {
            let secp_op = e.ctx.deploy_cell(system_script("secp256k1_blake160_sighash_all"));
            let data_op = e.ctx.deploy_cell(system_script("secp256k1_data"));
            let k = Privkey::from_slice(&[HOLDER; 32]);
            let pubkey = k.pubkey().expect("pubkey").serialize();
            let args = Bytes::from(blake2b_256(&pubkey)[..20].to_vec());
            let lock = e.ctx.build_script(&secp_op, args).expect("secp lock");
            (lock, Some(k), vec![CellDep::new_builder().out_point(data_op).build()])
        }
    }
}

fn id20(s: &Script) -> [u8; OWNER_HASH_LEN] {
    let mut h = [0u8; OWNER_HASH_LEN];
    h.copy_from_slice(&s.calc_script_hash().as_bytes()[..OWNER_HASH_LEN]);
    h
}
fn plain(cap: u64, lock: &Script) -> CellOutput {
    CellOutput::new_builder().capacity(cap.pack()).lock(lock.clone()).build()
}
fn typed(cap: u64, lock: &Script, type_: &Script) -> CellOutput {
    CellOutput::new_builder().capacity(cap.pack()).lock(lock.clone()).type_(Some(type_.clone()).pack()).build()
}
fn name_cell(e: &Env, cap: u64) -> CellOutput {
    typed(cap, &e.acct_lock, &e.acct_type)
}
fn input(op: OutPoint) -> CellInput {
    CellInput::new_builder().previous_output(op).build()
}
fn wit(input_type: Option<Bytes>, output_type: Option<Bytes>) -> packed::Bytes {
    let mut b = WitnessArgs::new_builder();
    if let Some(i) = input_type {
        b = b.input_type(Some(i).pack());
    }
    if let Some(o) = output_type {
        b = b.output_type(Some(o).pack());
    }
    b.build().as_bytes().pack()
}
fn witnesses_for(mut w: Vec<packed::Bytes>, n: usize) -> Vec<packed::Bytes> {
    while w.len() < n {
        w.push(wit(None, None));
    }
    w
}

/// Sign the lock group that starts at input `begin`, as `owner_consent.rs` does.
fn sign_group(tx: TransactionView, key: &Privkey, begin: usize, len: usize) -> TransactionView {
    let tx_hash = tx.hash();
    let n = tx.witnesses().len();
    let witnesses: Vec<packed::Bytes> = (0..n)
        .map(|i| {
            let w = tx.witnesses().get(i).expect("witness");
            if i != begin {
                return w;
            }
            let wa = WitnessArgs::new_unchecked(w.unpack());
            let zeroed = wa.clone().as_builder().lock(Some(Bytes::from(vec![0u8; 65])).pack()).build();
            let mut h = new_blake2b();
            h.update(&tx_hash.raw_data());
            let zb = zeroed.as_bytes();
            h.update(&(zb.len() as u64).to_le_bytes());
            h.update(&zb);
            for j in (begin + 1)..(begin + len) {
                let o = tx.witnesses().get(j).expect("witness");
                h.update(&(o.raw_data().len() as u64).to_le_bytes());
                h.update(&o.raw_data());
            }
            let mut msg = [0u8; 32];
            h.finalize(&mut msg);
            let sig = key.sign_recoverable(&H256::from(msg)).expect("sign");
            wa.as_builder().lock(Some(Bytes::from(sig.serialize())).pack()).build().as_bytes().pack()
        })
        .collect();
    tx.as_advanced_builder().set_witnesses(witnesses).build()
}

// --- a deed -----------------------------------------------------------------------------

/// `alice` is held as a deed: its owner and manager are the proxy lock over a Spore, and
/// under that lock sit the proxy cell and one meal. Somebody who holds no key of the
/// holder's spends the Spore and hands it back to the holder's lock with `TOP_UP` more,
/// which opens the proxy lock, and in the same transaction transfers `alice` to
/// themselves and keeps the proxy cell and the meal. Only `Holder::SecpSigned` carries the
/// holder's signature.
///
/// The Spore is modelled by a typed cell with 64 bytes of data under an always-success
/// type: the Spore contract's own rules are not what is tested, and the Spore comes back
/// byte for byte, as a Spore transfer to the same lock does.
fn stranger_takes_a_deed(holder: Holder) -> Result<u64, String> {
    let mut e = env();
    let (hlock, hkey, deps) = holder_lock(&mut e, holder);
    let spore_type = e.ctx.build_script(&e.plain_op, Bytes::from(vec![0x5B; 32])).expect("spore type");
    let proxy = e
        .ctx
        .build_script_with_hash_type(&e.proxy_op, ScriptHashType::Data1, spore_type.calc_script_hash().as_bytes())
        .expect("proxy lock");
    assert_eq!(proxy.code_hash().as_slice(), &h32(PROXY_CODE_HASH)[..], "the fixture is not input-type-proxy-lock");

    let (p, s) = (id20(&proxy), id20(&e.stranger));
    let empty = Bytes::new();
    let wh = ckb_blake2b256(&empty);
    let before = build_account_data(&wh, &ROOT_ID, NOW + ONE_YEAR, &p, &p, b"alice");
    let after = build_account_data(&wh, &ROOT_ID, NOW + ONE_YEAR, &s, &s, b"alice");
    let nc = name_cell(&e, NAME_CAP);
    let name_in = e.ctx.create_cell(nc.clone(), Bytes::from(before));
    let proxy_in = e.ctx.create_cell(plain(PROXY_CAP, &proxy), Bytes::from(vec![0x5A; 60]));
    let spore_data = Bytes::from(vec![0x77; 64]);
    let spore_in = e.ctx.create_cell(typed(SPORE_CAP, &hlock, &spore_type), spore_data.clone());
    let meal_in = e.ctx.create_cell(plain(MEAL_CAP, &proxy), Bytes::new());
    let funds = e.ctx.create_cell(plain(FUNDS, &e.stranger), Bytes::new());
    let inputs = vec![input(name_in), input(proxy_in), input(spore_in), input(meal_in), input(funds)];
    let outputs = vec![
        nc,
        typed(SPORE_CAP + TOP_UP, &hlock, &spore_type),
        plain(FUNDS + PROXY_CAP + MEAL_CAP - TOP_UP - TX_FEE, &e.stranger),
    ];
    let data = vec![Bytes::from(after), spore_data, Bytes::new()];
    let tx = TransactionBuilder::default()
        .inputs(inputs)
        .outputs(outputs)
        .outputs_data(data.pack())
        .cell_deps(deps)
        .witnesses(witnesses_for(vec![wit(Some(Bytes::from_static(b"transfer")), Some(empty))], 5))
        .build();
    let tx = e.ctx.complete_tx(tx);
    let tx = match (&hkey, holder) {
        (Some(k), Holder::SecpSigned) => sign_group(tx, k, 2, 1),
        _ => tx,
    };
    e.ctx.verify_tx(&tx, MAX_CYCLES).map_err(|x| format!("{x:?}"))
}

#[test]
fn a_stranger_cannot_take_a_deed_whose_spore_sits_under_a_listed_lock() {
    let results: Vec<(Listed, Result<u64, String>)> = LISTED
        .iter()
        .map(|&l| {
            let r = stranger_takes_a_deed(Holder::Listed(l));
            show(&format!("stranger tops up the holder's Spore and transfers the deed's name [{l:?}]"), &r);
            (l, r)
        })
        .collect();
    for (l, r) in &results {
        assert!(r.is_err(), "{l:?}: a stranger took a deed-held name through the proxy lock: {r:?}");
    }
}

#[test]
fn a_stranger_cannot_take_a_deed_whose_spore_sits_under_the_real_omnilock_in_anyone_can_pay_mode() {
    let r = stranger_takes_a_deed(Holder::Omnilock { acp: true });
    show("stranger tops up the holder's Spore under real Omnilock (acp) and transfers the name", &r);
    assert!(r.is_err(), "a stranger took a deed-held name through the real proxy lock and Omnilock: {r:?}");
}

/// The same transaction, signed by the holder: the shape is one the harness can pass.
#[test]
fn a_deed_holder_that_signs_moves_the_name() {
    let r = stranger_takes_a_deed(Holder::SecpSigned);
    show("the holder signs for the Spore and transfers the name", &r);
    assert!(r.is_ok(), "the holder's own transaction must pass, got {r:?}");
}

/// Without the holder's signature, a lock that needs one stops the stranger at the Spore.
#[test]
fn a_stranger_cannot_move_a_deed_whose_holder_must_sign() {
    let r = stranger_takes_a_deed(Holder::SecpUnsigned);
    show("stranger, holder under secp256k1, nobody signs", &r);
    let e = r.expect_err("an unsigned secp256k1 Spore must not open");
    assert!(e.contains("Inputs[2].Lock"), "the refusal must come from the holder's lock, got {e}");
}

/// The real Omnilock without its anyone-can-pay flag refuses the same stranger, so the
/// flag is what opens the Spore, and the real proxy lock and the contract do the rest.
#[test]
fn the_real_omnilock_without_the_flag_stops_the_stranger() {
    let r = stranger_takes_a_deed(Holder::Omnilock { acp: false });
    show("stranger, holder under real Omnilock without the flag, nobody signs", &r);
    let e = r.expect_err("Omnilock without the flag must want a signature");
    assert!(e.contains("Inputs[2].Lock"), "the refusal must come from the holder's lock, got {e}");
}

// --- a listing ------------------------------------------------------------------------------

/// `alice` is listed: owner and manager are the sale lock (seller, `PRICE`), with one offer
/// cell under it. Somebody spends the offer and, with `pay`, pays the seller and the
/// treasury exactly what a purchase pays. Instead of taking the name they run `action`:
/// `edit_manager` makes them the manager, `edit_records` writes their records, `transfer`
/// is the honest purchase.
fn pay_a_listing_and(build: Build, action: &'static [u8], pay: bool) -> Result<u64, String> {
    listing_tx(build, action, pay, false)
}

/// `pay_a_listing_and`, and with `seller_here` a cell of the seller's spent and handed back.
fn listing_tx(build: Build, action: &'static [u8], pay: bool, seller_here: bool) -> Result<u64, String> {
    let mut e = env_for(build);
    let seller = e.ctx.build_script(&e.plain_op, Bytes::from(vec![SELLER; 20])).expect("seller");
    let mut args = seller.calc_script_hash().raw_data().to_vec();
    args.extend_from_slice(&PRICE.to_le_bytes());
    let sale = e.ctx.build_script(&e.sale_op, Bytes::from(args)).expect("sale lock");
    let (l, s) = (id20(&sale), id20(&e.stranger));
    let empty = Bytes::new();
    let wh = ckb_blake2b256(&empty);
    let expiry = NOW + ONE_YEAR;
    let before = build_account_data(&wh, &ROOT_ID, expiry, &l, &l, b"alice");
    let (after, payload) = match action {
        b"transfer" => (build_account_data(&wh, &ROOT_ID, expiry, &s, &s, b"alice"), empty.clone()),
        b"edit_manager" => (build_account_data(&wh, &ROOT_ID, expiry, &l, &s, b"alice"), empty.clone()),
        _ => {
            let p = Bytes::from_static(b"records the payer chose");
            (build_account_data(&ckb_blake2b256(&p), &ROOT_ID, expiry, &l, &l, b"alice"), p)
        }
    };
    let nc = name_cell(&e, NAME_CAP);
    let name_in = e.ctx.create_cell(nc.clone(), Bytes::from(before));
    let offer_in = e.ctx.create_cell(plain(OFFER_CAP, &sale), Bytes::new());
    let funds = e.ctx.create_cell(plain(FUNDS, &e.stranger), Bytes::new());
    let mut outputs = vec![nc];
    let mut data = vec![Bytes::from(after)];
    let mut spent = 0;
    if pay {
        outputs.push(plain(TO_SELLER, &seller));
        outputs.push(plain(sale_fee(PRICE), &e.treasury));
        data.extend([Bytes::new(), Bytes::new()]);
        spent = TO_SELLER + sale_fee(PRICE);
    }
    outputs.push(plain(FUNDS + OFFER_CAP - spent - TX_FEE, &e.stranger));
    data.push(Bytes::new());
    let mut inputs = vec![input(name_in), input(offer_in), input(funds)];
    if seller_here {
        let own = e.ctx.create_cell(plain(100 * CKB, &seller), Bytes::new());
        inputs.push(input(own));
        outputs.push(plain(100 * CKB, &seller));
        data.push(Bytes::new());
    }
    let n = inputs.len();
    let tx = TransactionBuilder::default()
        .inputs(inputs)
        .outputs(outputs)
        .outputs_data(data.pack())
        .witnesses(witnesses_for(vec![wit(Some(Bytes::from_static(action)), Some(payload))], n))
        .build();
    let tx = e.ctx.complete_tx(tx);
    e.ctx.verify_tx(&tx, MAX_CYCLES).map_err(|x| format!("{x:?}"))
}

/// Somebody registers `shop.alice` for themselves while `alice` is listed, spending the
/// offer as the parent owner's consent and paying the seller and the treasury as a
/// purchase would, plus the sub-name's own fee. `alice` stays listed and stays the
/// seller's; the sub-name is the payer's, and a sub-name cannot be evicted (0008).
fn pay_a_listing_and_mint_a_sub_name(build: Build, pay: bool) -> Result<u64, String> {
    let mut e = env_for(build);
    let seller = e.ctx.build_script(&e.plain_op, Bytes::from(vec![SELLER; 20])).expect("seller");
    let mut args = seller.calc_script_hash().raw_data().to_vec();
    args.extend_from_slice(&PRICE.to_le_bytes());
    let sale = e.ctx.build_script(&e.sale_op, Bytes::from(args)).expect("sale lock");
    let (l, s) = (id20(&sale), id20(&e.stranger));
    let empty = Bytes::new();
    let wh = ckb_blake2b256(&empty);
    let label: &[u8] = b"shop.alice";
    let sub = account_id(label);
    let zero = [0u8; OWNER_HASH_LEN];
    let root_before = build_account_data(&wh, &ROOT_ID, 0, &zero, &zero, b"");
    let root_after = build_account_data(&wh, &sub, 0, &zero, &zero, b"");
    let child = build_account_data(&wh, &ROOT_ID, NOW + ONE_YEAR, &s, &s, label);
    let parent = build_account_data(&wh, &ROOT_ID, NOW + 2 * ONE_YEAR, &l, &l, b"alice");
    let nc = name_cell(&e, NAME_CAP);
    let parent_op = e.ctx.create_cell(nc.clone(), Bytes::from(parent));
    let root_in = e.ctx.create_cell(nc.clone(), Bytes::from(root_before));
    let secret = [0x77u8; SECRET_LEN];
    let commit = commitment(&e.ns, label, &s, &secret);
    let commit_in = e.ctx.create_cell(plain(100 * CKB, &e.stranger), Bytes::from(commit.to_vec()));
    let header = HeaderBuilder::default().timestamp(HEADER_TS_MS.pack()).build();
    e.ctx.insert_header(header.clone());
    e.ctx.link_cell_with_block(commit_in.clone(), header.hash(), 0);
    let offer_in = e.ctx.create_cell(plain(OFFER_CAP, &sale), Bytes::new());
    let funds = e.ctx.create_cell(plain(FUNDS, &e.stranger), Bytes::new());
    // The sub-name's fee, and on top of it the sale's (F-9: the account contract adds what
    // the sale locks in the transaction owe).
    let fee = registration_fee(label, 1) + sale_fee(PRICE);
    let mut outputs = vec![nc.clone(), nc, plain(fee, &e.treasury)];
    let mut data = vec![Bytes::from(root_after), Bytes::from(child), Bytes::new()];
    let mut to_seller = 0;
    if pay {
        outputs.push(plain(TO_SELLER, &seller));
        data.push(Bytes::new());
        to_seller = TO_SELLER;
    }
    outputs.push(plain(FUNDS + 100 * CKB + OFFER_CAP - NAME_CAP - fee - to_seller - TX_FEE, &e.stranger));
    data.push(Bytes::new());
    let inputs = vec![
        input(root_in),
        CellInput::new_builder()
            .since((0xC000_0000_0000_0000u64 | COMMIT_MIN_DELAY).pack())
            .previous_output(commit_in)
            .build(),
        input(offer_in),
        input(funds),
    ];
    let n = inputs.len().max(outputs.len());
    let tx = TransactionBuilder::default()
        .inputs(inputs)
        .outputs(outputs)
        .outputs_data(data.pack())
        .cell_dep(CellDep::new_builder().out_point(parent_op).build())
        .header_dep(header.hash())
        .witnesses(witnesses_for(
            vec![
                wit(Some(Bytes::from_static(b"register")), Some(empty.clone())),
                wit(Some(Bytes::from(secret.to_vec())), Some(empty)),
            ],
            n,
        ))
        .build();
    let tx = e.ctx.complete_tx(tx);
    e.ctx.verify_tx(&tx, MAX_CYCLES).map_err(|x| format!("{x:?}"))
}

#[test]
fn paying_a_listing_does_not_buy_the_manager_seat() {
    let r = pay_a_listing_and(Build::Test, b"edit_manager", true);
    show("pay the listing in full, set yourself as manager, leave the name listed", &r);
    assert!(r.is_err(), "the price bought the manager seat of a name that stays listed: {r:?}");
}

#[test]
fn paying_a_listing_does_not_buy_its_records() {
    let r = pay_a_listing_and(Build::Test, b"edit_records", true);
    show("pay the listing in full, rewrite its records, leave the name listed", &r);
    assert!(r.is_err(), "the price bought the records of a name that stays listed: {r:?}");
}

#[test]
fn paying_a_listing_does_not_mint_a_sub_name_under_it() {
    let r = pay_a_listing_and_mint_a_sub_name(Build::Test, true);
    show("pay the parent's listing in full, register shop.alice, leave alice listed", &r);
    assert!(r.is_err(), "the price bought a sub-name under a name that stays listed: {r:?}");
}

/// The controls: the purchase itself passes, and without the payment none of it does.
#[test]
fn a_listing_opens_only_for_the_price() {
    let r = pay_a_listing_and(Build::Test, b"transfer", true);
    show("pay the listing in full and take the name (a purchase)", &r);
    assert!(r.is_ok(), "an honest purchase must pass, got {r:?}");
    for action in [&b"edit_manager"[..], b"edit_records", b"transfer"] {
        let r = pay_a_listing_and(Build::Test, action, false);
        show(&format!("spend the offer without paying, {}", String::from_utf8_lossy(action)), &r);
        assert_code(&r, 3, "an unpaid offer");
    }
    let r = pay_a_listing_and_mint_a_sub_name(Build::Test, false);
    show("spend the parent's offer without paying the seller, register shop.alice", &r);
    assert_code(&r, 3, "an unpaid offer as a parent's consent");
}

/// The seller keeps every owner act while the name is listed: with a cell of theirs in the
/// transaction the listing opens without a payment, as it always has.
#[test]
fn a_seller_who_is_here_still_manages_a_listed_name() {
    for action in [&b"edit_manager"[..], b"edit_records", b"transfer"] {
        let r = listing_tx(Build::Test, action, false, true);
        show(&format!("seller here, nothing paid, {}", String::from_utf8_lossy(action)), &r);
        assert!(r.is_ok(), "the seller must still act on a listed name, got {r:?}");
    }
}

/// The same three, against the contracts live on mainnet today.
#[test]
#[ignore = "open on mainnet as deployed: paying a listing buys any one owner action, not only the transfer"]
fn on_mainnet_as_deployed_paying_a_listing_buys_one_owner_action() {
    let results = [
        ("pay the listing in full, set yourself as manager, leave it listed", pay_a_listing_and(Build::Mainnet, b"edit_manager", true)),
        ("pay the listing in full, rewrite its records, leave it listed", pay_a_listing_and(Build::Mainnet, b"edit_records", true)),
        ("pay the parent's listing in full, register shop.alice, leave alice listed", pay_a_listing_and_mint_a_sub_name(Build::Mainnet, true)),
    ];
    for (what, r) in &results {
        show(&format!("mainnet binaries: {what}"), r);
    }
    for (what, r) in &results {
        assert!(r.is_err(), "mainnet binaries: {what}: {r:?}");
    }
}

#[test]
fn on_mainnet_as_deployed_a_listing_opens_only_for_the_price() {
    let r = pay_a_listing_and(Build::Mainnet, b"transfer", true);
    show("mainnet binaries: pay the listing in full and take the name (a purchase)", &r);
    assert!(r.is_ok(), "an honest purchase must pass on the mainnet binaries, got {r:?}");
    for action in [&b"edit_manager"[..], b"edit_records", b"transfer"] {
        let r = pay_a_listing_and(Build::Mainnet, action, false);
        show(&format!("mainnet binaries: spend the offer without paying, {}", String::from_utf8_lossy(action)), &r);
        assert_code(&r, 3, "an unpaid offer on the mainnet binaries");
    }
    let r = pay_a_listing_and_mint_a_sub_name(Build::Mainnet, false);
    show("mainnet binaries: spend the parent's offer without paying the seller, register shop.alice", &r);
    assert_code(&r, 3, "an unpaid offer as a parent's consent on the mainnet binaries");
}

// --- which locks the list refuses -------------------------------------------------------

/// Every lock the app and the SDK really make an owner, manager, seller or holder with,
/// by code hash on both networks (CCC 1.19.1 known scripts, `sdk/src/pq.ts`,
/// `sdk/src/deployments.ts`), is not refused, with the args those wallets write.
#[test]
fn no_lock_an_owner_really_uses_is_refused() {
    let key20 = [0x11u8; 20].to_vec();
    let omni = |auth: u8| {
        let mut a = vec![auth];
        a.extend_from_slice(&[0x11; 20]);
        a.push(0);
        a
    };
    let honest: [(&str, &str, Vec<u8>); 18] = [
        ("secp256k1", "9bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce8", key20.clone()),
        ("multisig, legacy", "5c5069eb0857efc65e1bca0c07df34c31663b3622fd3876c876320fc9634e2a8", key20.clone()),
        ("multisig v2", "36c971b8d41fbd94aabca77dc75e826729ac98447b46f91e00796155dddb0d29", key20.clone()),
        ("multisig v2 beta, mainnet", "d1a9f877aed3f5e07cb9c52b61ab96d06f250ae6883cc7f0a2423db0976fc821", key20.clone()),
        ("multisig v2 beta, testnet", "765b3ed6ae264b335d07e73ac332bf2c0f38f8d3340ed521cb447b4c42dd5f09", key20.clone()),
        ("JoyID, mainnet", "d00c84f0ec8fd441c38bc3f87a371f547190f2fcff88e642bc5bf54b9e318323", [0x00, 0x01].iter().chain(&[0x11; 20]).copied().collect()),
        ("JoyID, testnet", "d23761b364210735c19c60561d213fb3beae2fd6172743719eff6920e020baac", [0x00, 0x01].iter().chain(&[0x11; 20]).copied().collect()),
        ("Omnilock EVM, mainnet", "9b819793a64463aed77c615d6cb226eea5487ccfc0783043a587254cda2b6f26", omni(0x12)),
        ("Omnilock EVM, testnet", "f329effd1c475a2978453c8600e1eaf0bc2087ee093c3ee64cc96ec6847752cb", omni(0x12)),
        ("Omnilock BTC, mainnet", "9b819793a64463aed77c615d6cb226eea5487ccfc0783043a587254cda2b6f26", omni(0x04)),
        ("Omnilock Doge, testnet", "f329effd1c475a2978453c8600e1eaf0bc2087ee093c3ee64cc96ec6847752cb", omni(0x05)),
        ("Nostr, mainnet", "641a89ad2f77721b803cd50d01351c1f308444072d5fa20088567196c0574c68", key20.clone()),
        ("Nostr, testnet", "6ae5ee0cb887b2df5a9a18137315b9bdc55be8d52637b2de0624092d5f0c91d5", key20.clone()),
        ("SPHINCS+, mainnet", "302d35982f865ebcbedb9a9360e40530ed32adb8e10b42fbbe70d8312ff7cedf", vec![0x22; 32]),
        ("SPHINCS+, testnet", "147ecbb5c5127d982ee1362d2c2bb4267803da2eb006d150e88af6caaa0a7eaf", vec![0x22; 32]),
        ("input-type-proxy-lock (a deed)", PROXY_CODE_HASH, vec![0x33; 32]),
        ("sale lock, mainnet", "086c8f4e9d4272e3dfbaca399792f730e6604591e87931ee6d67047a3c900879", vec![0x44; 40]),
        ("sale lock, testnet", "498ab6b49b6b25b3c47fcea74bd8a4447bc4efda6417809152a846e058ad0ae4", vec![0x44; 40]),
    ];
    for (what, code_hash, args) in honest.iter() {
        assert!(!lets_anyone_spend(&h32(code_hash), args), "{what} is refused as consent");
    }
    // And the list itself, with the args those locks are addressed by.
    for h in ANYONE_CAN_PAY_CODE_HASHES {
        assert!(lets_anyone_spend(&h, &key20));
    }
    for h in OMNILOCK_CODE_HASHES {
        assert!(lets_anyone_spend(&h, &omnilock_args(0x11, OMNILOCK_ANYONE_CAN_PAY)));
    }
}
