//! Which inputs count as consent, and which offers can be bought. From the review of
//! 2026-09-27, reproduced here against the contracts as they were before either changed.
//!
//! **Owner consent.** `account-cell-type` takes a transaction as the owner's act when it
//! spends a cell under the owner's lock (`require_owner`, `require_owner_or_manager`, the
//! commit holder), and `sale-lock` takes it as the seller's when it spends a cell under the
//! seller's lock. Under an anyone-can-pay lock (RFC 0026) a stranger may spend the owner's
//! cell with no key by handing it back topped up, so that stranger could act as the owner:
//! transfer the name, rewrite its records, set its manager, mint and renew sub-names, and
//! take a listed name unpaid.
//!
//! The locks here are the deployed ones by code hash: each code cell is recreated under
//! the type-id args it has on chain, so the list compiled into the contracts is what is
//! tested, not a copy of it. Their code in the mock VM is always-success, which is what
//! the real ones allow a stranger who tops the cell up. The controls use the real
//! secp256k1 lock, which refuses an unsigned spend by itself.
//!
//! **Offers by data hash.** `account-cell-type` knows the sale lock by its type id (F-9).
//! The same binary named by its data hash is a sale lock it does not know, so beside a
//! renewal one treasury output answered both fees. An offer is now bought only by type id.
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
    account_id, build_account_data, ckb_blake2b256, commitment, registration_fee, sale_fee,
    ANYONE_CAN_PAY_CODE_HASHES, COMMIT_MIN_DELAY, NAMESPACE_LEN, OMNILOCK_ANYONE_CAN_PAY,
    OMNILOCK_CODE_HASHES, OWNER_HASH_LEN, ROOT_ID, SECRET_LEN,
};
use tests::Loader;

const MAX_CYCLES: u64 = 100_000_000;
const CKB: u64 = 100_000_000;
const HEADER_TS_MS: u64 = 1_700_000_000_000;
const NOW: u64 = HEADER_TS_MS / 1000;
const ONE_YEAR: u64 = 365 * 86_400;
const NAME_CAP: u64 = 300 * CKB;
/// The cell under a party's lock that the stranger spends and gives back.
const PLATE: u64 = 100 * CKB;
/// What the stranger adds to it, the anyone-can-pay condition.
const TOP_UP: u64 = CKB;
const FUNDS: u64 = 100_000 * CKB;
const TX_FEE: u64 = 1_000;
const PRICE: u64 = 10_000 * CKB;
const OFFER_CAP: u64 = 100 * CKB;
const TO_SELLER: u64 = PRICE - sale_fee(PRICE) + OFFER_CAP;
/// A deed's proxy cell: 60 bytes of data under the proxy lock (sdk/src/deed.ts).
const PROXY_CAP: u64 = 133 * CKB;
/// One byte per party, so every party's lock hashes differently.
const OWNER: u8 = 0x0A;
const MANAGER: u8 = 0x0B;
const HOLDER: u8 = 0x0C;

fn h32(s: &str) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (i, o) in out.iter_mut().enumerate() {
        *o = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).expect("hex");
    }
    out
}

fn assert_code(res: &Result<u64, String>, code: i32, what: &str) {
    let e = res.as_ref().err().unwrap_or_else(|| panic!("{what}: expected a failure, it passed"));
    assert!(e.contains(&format!("error code {code} ")), "{what}: wanted error {code}, got {e}");
}

fn show(what: &str, res: &Result<u64, String>) {
    match res {
        Ok(c) => println!("{what}: ACCEPTED ({c} cycles)"),
        Err(e) => {
            // The source and the code are what matter; the rest is a URL.
            let short = e.split(" on page").next().unwrap_or(e);
            println!("{what}: REJECTED {short}");
        }
    }
}

// --- the locks ------------------------------------------------------------------------

/// A lock the contracts must not take as anybody's consent, as deployed.
#[derive(Clone, Copy, Debug)]
enum Listed {
    AnyoneCanPayMainnet,
    AnyoneCanPayTestnet,
    PwLockMainnet,
    PwLockTestnet,
    OmnilockAcpMainnet,
    OmnilockAcpTestnet,
    /// The older testnet deployments, still live and still holding cells (2026-09-27).
    AnyoneCanPayTestnetOld,
    OmnilockAcpTestnetOld,
}

const LISTED: [Listed; 8] = [
    Listed::AnyoneCanPayMainnet,
    Listed::AnyoneCanPayTestnet,
    Listed::PwLockMainnet,
    Listed::PwLockTestnet,
    Listed::OmnilockAcpMainnet,
    Listed::OmnilockAcpTestnet,
    Listed::AnyoneCanPayTestnetOld,
    Listed::OmnilockAcpTestnetOld,
];

impl Listed {
    /// The type-id args of the lock's code cell, read from each chain on 2026-09-27 (the
    /// cells CCC's known scripts point at).
    fn type_id_args(self) -> [u8; 32] {
        h32(match self {
            Listed::AnyoneCanPayMainnet => "de8b879bd1e98399de0dc9be163e703fc1fb82d9379ee1e85143b9f5a863610c",
            Listed::AnyoneCanPayTestnet => "b9c8cb04f45fc2ad69cc37c14a70e601a4236369b9cb0bb1fff1e386d5ffde46",
            Listed::PwLockMainnet => "42ade2f25eb938b5dbfd3d8f07b8b07aa593d848e7ff14bdfbbea5aeb6175261",
            Listed::PwLockTestnet => "f6d90bfe3041d0fd7e01c45770241697f5f837974bd6ae1672a7ec0f9f523268",
            Listed::OmnilockAcpMainnet => "855508fe0f0ca25b935b070452ecaee48f6c9f1d66cd15f046616b99e948236a",
            Listed::OmnilockAcpTestnet => "761f51fc9cd6a504c32c6ae64b3746594d1af27629b427c5ccf6c9a725a89144",
            Listed::AnyoneCanPayTestnetOld => "fe01c6c37736f0a006992fd6146b15a3337b7f9aa298987681bd5a1076a59bdd",
            Listed::OmnilockAcpTestnetOld => "1b8572b16c07f46a0efed623aea6de05d45985b9a7c1b0b52276da5d9f9615b7",
        })
    }

    /// Where the contracts list it.
    fn listed_as(self) -> [u8; 32] {
        match self {
            Listed::AnyoneCanPayMainnet => ANYONE_CAN_PAY_CODE_HASHES[0],
            Listed::AnyoneCanPayTestnet => ANYONE_CAN_PAY_CODE_HASHES[1],
            Listed::PwLockMainnet => ANYONE_CAN_PAY_CODE_HASHES[2],
            Listed::PwLockTestnet => ANYONE_CAN_PAY_CODE_HASHES[3],
            Listed::OmnilockAcpMainnet => OMNILOCK_CODE_HASHES[0],
            Listed::OmnilockAcpTestnet => OMNILOCK_CODE_HASHES[1],
            Listed::AnyoneCanPayTestnetOld => ANYONE_CAN_PAY_CODE_HASHES[4],
            Listed::OmnilockAcpTestnetOld => OMNILOCK_CODE_HASHES[2],
        }
    }

    /// An owner's args under it: a 20-byte key hash, which is all an anyone-can-pay or a
    /// PW-lock address carries, and for Omnilock the flags byte with the bit set.
    fn owner_args(self, key: u8) -> Bytes {
        match self {
            Listed::OmnilockAcpMainnet | Listed::OmnilockAcpTestnet | Listed::OmnilockAcpTestnetOld => {
                omnilock_args(key, OMNILOCK_ANYONE_CAN_PAY)
            }
            _ => Bytes::from(vec![key; 20]),
        }
    }
}

/// Omnilock args: auth flag 0x12 (an Ethereum key, as CCC's EVM signer writes it), the
/// 20-byte id, the flags byte, and the two minimums the anyone-can-pay flag requires.
fn omnilock_args(key: u8, flags: u8) -> Bytes {
    let mut a = vec![0x12];
    a.extend_from_slice(&[key; 20]);
    a.push(flags);
    if flags & OMNILOCK_ANYONE_CAN_PAY != 0 {
        a.extend_from_slice(&[0, 0]);
    }
    Bytes::from(a)
}

/// Whose lock a party's cells are under.
#[derive(Clone, Copy, Debug)]
enum Owner {
    /// A lock on the list.
    Listed(Listed),
    /// Omnilock without the flag: an ordinary key, which must keep working.
    Omnilock,
    /// An anyone-can-pay lock the list does not know, under a type id of its own.
    Unlisted,
    /// The harness's usual party: always-success with its own args.
    Plain,
    /// secp256k1_blake160_sighash_all, and nobody signs for it.
    SecpUnsigned,
    /// The same, signed by its key: proves the harness can pass at all.
    SecpSigned,
}

struct Env {
    ctx: Context,
    acct_type: Script,
    acct_lock: Script,
    plain_op: OutPoint,
    sale_op: OutPoint,
    stranger: Script,
    treasury: Script,
    ns: [u8; NAMESPACE_LEN],
}

fn env() -> Env {
    let mut ctx = Context::default();
    let acct_op = ctx.deploy_cell(Loader::default().load_binary("account-cell-type"));
    let sale_op = tests::deploy_sale_lock(&mut ctx);
    // Before any lock is recreated from always-success below: `deploy_cell` hands back
    // whichever cell was registered last under a binary's data hash.
    let plain_op = ctx.deploy_cell(ALWAYS_SUCCESS.clone());
    let token = ctx.build_script(&plain_op, Bytes::from_static(b"genesis-token")).expect("token");
    let mut ns = [0u8; NAMESPACE_LEN];
    ns.copy_from_slice(&token.calc_script_hash().as_bytes()[..NAMESPACE_LEN]);
    let acct_type = ctx.build_script(&acct_op, Bytes::from(ns.to_vec())).expect("acct type");
    let acct_lock = ctx.build_script(&plain_op, Bytes::from_static(b"cells-account-lock")).expect("acct lock");
    let stranger = ctx.build_script(&plain_op, Bytes::from_static(b"stranger")).expect("stranger");
    // Data1 and these args: the treasury the test build was compiled against.
    let treasury = ctx
        .build_script_with_hash_type(&plain_op, ScriptHashType::Data1, Bytes::from_static(b"treasury"))
        .expect("treasury");
    Env { ctx, acct_type, acct_lock, plain_op, sale_op, stranger, treasury, ns }
}

fn system_script(name: &str) -> Bytes {
    let bin = ckb_system_scripts::BUNDLED_CELL.get(&format!("specs/cells/{name}")).expect("bundled system script");
    Bytes::from(bin.to_vec())
}

/// A lock whose code cell is recreated under `type_id` with always-success in it.
fn recreated(e: &mut Env, type_id: [u8; 32], args: Bytes) -> Script {
    let op = tests::deploy_under_type_id(&mut e.ctx, type_id, ALWAYS_SUCCESS.clone());
    e.ctx.build_script(&op, args).expect("lock")
}

/// A lock of kind `who` for `key`, the key that signs for it (only `SecpSigned` uses
/// it), and the cell deps it needs.
fn lock_of(e: &mut Env, who: Owner, key: u8) -> (Script, Option<Privkey>, Vec<CellDep>) {
    match who {
        Owner::Listed(l) => (recreated(e, l.type_id_args(), l.owner_args(key)), None, vec![]),
        Owner::Omnilock => {
            (recreated(e, Listed::OmnilockAcpMainnet.type_id_args(), omnilock_args(key, 0)), None, vec![])
        }
        Owner::Unlisted => (recreated(e, *b"an anyone-can-pay the list lacks", Bytes::from(vec![key; 20])), None, vec![]),
        Owner::Plain => (e.ctx.build_script(&e.plain_op, Bytes::from(vec![key; 20])).expect("plain"), None, vec![]),
        Owner::SecpUnsigned | Owner::SecpSigned => {
            let secp_op = e.ctx.deploy_cell(system_script("secp256k1_blake160_sighash_all"));
            let data_op = e.ctx.deploy_cell(system_script("secp256k1_data"));
            let k = Privkey::from_slice(&[key; 32]);
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
fn name_cell(e: &Env, cap: u64) -> CellOutput {
    CellOutput::new_builder()
        .capacity(cap.pack())
        .lock(e.acct_lock.clone())
        .type_(Some(e.acct_type.clone()).pack())
        .build()
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
/// Pad the witnesses to one per input, the shape every lock and the type script expect.
fn witnesses_for(mut w: Vec<packed::Bytes>, n: usize) -> Vec<packed::Bytes> {
    while w.len() < n {
        w.push(wit(None, None));
    }
    w
}

/// Sign the lock group that starts at input `begin`, the way ckb-system-scripts 0.5.4's
/// own tests do (sighash over the group's witnesses).
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

// --- the transactions -------------------------------------------------------------------

/// Which party's cell the stranger spends and hands back.
#[derive(Clone, Copy, PartialEq)]
enum Plate {
    None,
    Owner,
    Manager,
}

/// A stranger acts on `alice`, owned by `owner` and managed by `manager` (the owner when
/// `None`): `transfer` hands it to the stranger, `edit_records` writes records the
/// stranger chose, `edit_manager` makes the stranger its manager. With a plate, the
/// stranger also spends a cell under that party's lock and gives it back topped up by
/// `TOP_UP` from their own funds, which is exactly what anyone-can-pay permits. Nobody
/// signs for the owner; only `SecpSigned` carries the owner's key.
fn stranger_acts(owner: Owner, manager: Option<Owner>, action: &'static [u8], plate: Plate) -> Result<u64, String> {
    let mut e = env();
    let (olock, okey, mut deps) = lock_of(&mut e, owner, OWNER);
    let mlock = match manager {
        Some(m) => {
            let (l, _, d) = lock_of(&mut e, m, MANAGER);
            deps.extend(d);
            l
        }
        None => olock.clone(),
    };
    let (o, m, s) = (id20(&olock), id20(&mlock), id20(&e.stranger));
    let empty = Bytes::new();
    let wh = ckb_blake2b256(&empty);
    let expiry = NOW + ONE_YEAR;
    let before = build_account_data(&wh, &ROOT_ID, expiry, &o, &m, b"alice");
    let (after, payload) = match action {
        b"transfer" => (build_account_data(&wh, &ROOT_ID, expiry, &s, &s, b"alice"), empty.clone()),
        b"edit_manager" => (build_account_data(&wh, &ROOT_ID, expiry, &o, &s, b"alice"), empty.clone()),
        _ => {
            let p = Bytes::from_static(b"records the stranger chose");
            (build_account_data(&ckb_blake2b256(&p), &ROOT_ID, expiry, &o, &m, b"alice"), p)
        }
    };
    let nc = name_cell(&e, NAME_CAP);
    let name_in = e.ctx.create_cell(nc.clone(), Bytes::from(before));
    let mut inputs = vec![input(name_in)];
    let mut outputs = vec![nc];
    let mut data = vec![Bytes::from(after)];
    let plate_lock = match plate {
        Plate::Owner => Some(olock.clone()),
        Plate::Manager => Some(mlock.clone()),
        Plate::None => None,
    };
    if let Some(l) = &plate_lock {
        let cell = e.ctx.create_cell(plain(PLATE, l), Bytes::new());
        inputs.push(input(cell));
        outputs.push(plain(PLATE + TOP_UP, l));
        data.push(Bytes::new());
    }
    let funds = e.ctx.create_cell(plain(FUNDS, &e.stranger), Bytes::new());
    inputs.push(input(funds));
    outputs.push(plain(FUNDS - TOP_UP - TX_FEE, &e.stranger));
    data.push(Bytes::new());
    let n = inputs.len();
    let tx = TransactionBuilder::default()
        .inputs(inputs)
        .outputs(outputs)
        .outputs_data(data.pack())
        .cell_deps(deps)
        .witnesses(witnesses_for(vec![wit(Some(Bytes::from_static(action)), Some(payload))], n))
        .build();
    let tx = e.ctx.complete_tx(tx);
    let tx = match (&okey, owner, plate) {
        (Some(k), Owner::SecpSigned, Plate::Owner) => sign_group(tx, k, 1, 1),
        _ => tx,
    };
    e.ctx.verify_tx(&tx, MAX_CYCLES).map_err(|x| format!("{x:?}"))
}

/// Somebody registers `shop.alice` for themselves. The parent `alice` is owned by
/// `parent` and presented as a cell dep. With `plate = Some(extra)`, a cell under the
/// parent owner's lock is spent and handed back with `extra` more: `TOP_UP` is the
/// stranger's anyone-can-pay move, zero is the SDK's co-sign, where the parent's owner
/// signs and pays nothing ("co-signing costs the parent's owner nothing but a signature").
fn register_sub_name(parent: Owner, plate: Option<u64>) -> Result<u64, String> {
    let mut e = env();
    let (plock, _, deps) = lock_of(&mut e, parent, OWNER);
    let p = id20(&plock);
    let s = id20(&e.stranger);
    let empty = Bytes::new();
    let wh = ckb_blake2b256(&empty);
    let label: &[u8] = b"shop.alice";
    let sub = account_id(label);
    let zero = [0u8; OWNER_HASH_LEN];
    let root_before = build_account_data(&wh, &ROOT_ID, 0, &zero, &zero, b"");
    let root_after = build_account_data(&wh, &sub, 0, &zero, &zero, b"");
    let child = build_account_data(&wh, &ROOT_ID, NOW + ONE_YEAR, &s, &s, label);
    let parent_data = build_account_data(&wh, &ROOT_ID, NOW + 2 * ONE_YEAR, &p, &p, b"alice");
    let nc = name_cell(&e, NAME_CAP);
    let parent_op = e.ctx.create_cell(nc.clone(), Bytes::from(parent_data));
    let root_in = e.ctx.create_cell(nc.clone(), Bytes::from(root_before));
    let secret = [0x77u8; SECRET_LEN];
    let commit = commitment(&e.ns, label, &s, &secret);
    let commit_in = e.ctx.create_cell(plain(PLATE, &e.stranger), Bytes::from(commit.to_vec()));
    let header = HeaderBuilder::default().timestamp(HEADER_TS_MS.pack()).build();
    e.ctx.insert_header(header.clone());
    e.ctx.link_cell_with_block(commit_in.clone(), header.hash(), 0);
    let fee = registration_fee(label, 1);

    let mut inputs = vec![
        input(root_in),
        CellInput::new_builder()
            .since((0xC000_0000_0000_0000u64 | COMMIT_MIN_DELAY).pack())
            .previous_output(commit_in)
            .build(),
    ];
    let mut outputs = vec![nc.clone(), nc, plain(fee, &e.treasury)];
    let mut data = vec![Bytes::from(root_after), Bytes::from(child), Bytes::new()];
    let mut top_up = 0;
    if let Some(extra) = plate {
        let cell = e.ctx.create_cell(plain(PLATE, &plock), Bytes::new());
        inputs.push(input(cell));
        outputs.push(plain(PLATE + extra, &plock));
        data.push(Bytes::new());
        top_up = extra;
    }
    let funds = e.ctx.create_cell(plain(FUNDS, &e.stranger), Bytes::new());
    inputs.push(input(funds));
    outputs.push(plain(FUNDS + PLATE - NAME_CAP - fee - top_up - TX_FEE, &e.stranger));
    data.push(Bytes::new());
    let n = inputs.len().max(outputs.len());
    let witnesses = witnesses_for(
        vec![
            wit(Some(Bytes::from_static(b"register")), Some(empty.clone())),
            wit(Some(Bytes::from(secret.to_vec())), Some(empty)),
        ],
        n,
    );
    let tx = TransactionBuilder::default()
        .inputs(inputs)
        .outputs(outputs)
        .outputs_data(data.pack())
        .cell_dep(CellDep::new_builder().out_point(parent_op).build())
        .cell_deps(deps)
        .header_dep(header.hash())
        .witnesses(witnesses)
        .build();
    let tx = e.ctx.complete_tx(tx);
    e.ctx.verify_tx(&tx, MAX_CYCLES).map_err(|x| format!("{x:?}"))
}

/// Somebody renews `shop.alice` for a year. Since 2026-09-17 a sub-name lives at the
/// pleasure of its parent's owner, so this needs the parent owner's input, exactly as
/// `register_sub_name` does.
fn renew_sub_name(parent: Owner, plate: Option<u64>) -> Result<u64, String> {
    let mut e = env();
    let (plock, _, deps) = lock_of(&mut e, parent, OWNER);
    let p = id20(&plock);
    let s = id20(&e.stranger);
    let empty = Bytes::new();
    let wh = ckb_blake2b256(&empty);
    let label: &[u8] = b"shop.alice";
    let before = build_account_data(&wh, &ROOT_ID, NOW + ONE_YEAR, &s, &s, label);
    let after = build_account_data(&wh, &ROOT_ID, NOW + 2 * ONE_YEAR, &s, &s, label);
    let parent_data = build_account_data(&wh, &ROOT_ID, NOW + 3 * ONE_YEAR, &p, &p, b"alice");
    let nc = name_cell(&e, NAME_CAP);
    let parent_op = e.ctx.create_cell(nc.clone(), Bytes::from(parent_data));
    let child_in = e.ctx.create_cell(nc.clone(), Bytes::from(before));
    let fee = registration_fee(label, 1);
    let mut inputs = vec![input(child_in)];
    let mut outputs = vec![nc, plain(fee, &e.treasury)];
    let mut data = vec![Bytes::from(after), Bytes::new()];
    let mut top_up = 0;
    if let Some(extra) = plate {
        let cell = e.ctx.create_cell(plain(PLATE, &plock), Bytes::new());
        inputs.push(input(cell));
        outputs.push(plain(PLATE + extra, &plock));
        data.push(Bytes::new());
        top_up = extra;
    }
    let funds = e.ctx.create_cell(plain(FUNDS, &e.stranger), Bytes::new());
    inputs.push(input(funds));
    outputs.push(plain(FUNDS - fee - top_up - TX_FEE, &e.stranger));
    data.push(Bytes::new());
    let n = inputs.len().max(outputs.len());
    let tx = TransactionBuilder::default()
        .inputs(inputs)
        .outputs(outputs)
        .outputs_data(data.pack())
        .cell_dep(CellDep::new_builder().out_point(parent_op).build())
        .cell_deps(deps)
        .witnesses(witnesses_for(vec![wit(Some(Bytes::from_static(b"renew")), Some(empty))], n))
        .build();
    let tx = e.ctx.complete_tx(tx);
    e.ctx.verify_tx(&tx, MAX_CYCLES).map_err(|x| format!("{x:?}"))
}

/// A stranger lands the registration of `alice` for an owner under `owner`, holding the
/// CommitCell under the owner's own lock: the commitment is public once committed, so it
/// can be copied into a cell anybody sends to that lock, and under an anyone-can-pay lock
/// anybody can spend that cell again by handing its capacity back. The name goes to the
/// committed owner; everything else about it (term, records) is the stranger's choice.
fn stranger_lands_registration(owner: Owner) -> Result<u64, String> {
    let mut e = env();
    let (olock, _, deps) = lock_of(&mut e, owner, OWNER);
    let o = id20(&olock);
    let empty = Bytes::new();
    let wh = ckb_blake2b256(&empty);
    let label: &[u8] = b"alice";
    let x = account_id(label);
    let zero = [0u8; OWNER_HASH_LEN];
    let root_before = build_account_data(&wh, &ROOT_ID, 0, &zero, &zero, b"");
    let root_after = build_account_data(&wh, &x, 0, &zero, &zero, b"");
    let name = build_account_data(&wh, &ROOT_ID, NOW + ONE_YEAR, &o, &o, label);
    let nc = name_cell(&e, NAME_CAP);
    let root_in = e.ctx.create_cell(nc.clone(), Bytes::from(root_before));
    let secret = [0x77u8; SECRET_LEN];
    let commit = commitment(&e.ns, label, &o, &secret);
    let commit_in = e.ctx.create_cell(plain(PLATE, &olock), Bytes::from(commit.to_vec()));
    let header = HeaderBuilder::default().timestamp(HEADER_TS_MS.pack()).build();
    e.ctx.insert_header(header.clone());
    e.ctx.link_cell_with_block(commit_in.clone(), header.hash(), 0);
    let fee = registration_fee(label, 1);
    let funds = e.ctx.create_cell(plain(FUNDS, &e.stranger), Bytes::new());
    let inputs = vec![
        input(root_in),
        CellInput::new_builder()
            .since((0xC000_0000_0000_0000u64 | COMMIT_MIN_DELAY).pack())
            .previous_output(commit_in)
            .build(),
        input(funds),
    ];
    let outputs = vec![
        nc.clone(),
        nc,
        plain(fee, &e.treasury),
        // The commit cell's capacity back under the owner's lock, topped up.
        plain(PLATE + TOP_UP, &olock),
        plain(FUNDS - NAME_CAP - fee - TOP_UP - TX_FEE, &e.stranger),
    ];
    let data = vec![Bytes::from(root_after), Bytes::from(name), Bytes::new(), Bytes::new(), Bytes::new()];
    let witnesses = witnesses_for(
        vec![
            wit(Some(Bytes::from_static(b"register")), Some(empty.clone())),
            wit(Some(Bytes::from(secret.to_vec())), Some(empty)),
        ],
        5,
    );
    let tx = TransactionBuilder::default()
        .inputs(inputs)
        .outputs(outputs)
        .outputs_data(data.pack())
        .cell_deps(deps)
        .header_dep(header.hash())
        .witnesses(witnesses)
        .build();
    let tx = e.ctx.complete_tx(tx);
    e.ctx.verify_tx(&tx, MAX_CYCLES).map_err(|x| format!("{x:?}"))
}

/// Somebody takes `alice`, listed under the sale lock by a seller under `seller`, and pays
/// nobody. With `seller_input`, a cell under the seller's lock is spent and handed back
/// topped up, which is the sale lock's "the seller is here" branch.
fn take_listed_name(seller: Owner, seller_input: bool) -> Result<u64, String> {
    let mut e = env();
    let (slock, _, deps) = lock_of(&mut e, seller, OWNER);
    let mut args = slock.calc_script_hash().raw_data().to_vec();
    args.extend_from_slice(&PRICE.to_le_bytes());
    let sale = e.ctx.build_script(&e.sale_op, Bytes::from(args)).expect("sale lock");
    let listed = id20(&sale);
    let s = id20(&e.stranger);
    let empty = Bytes::new();
    let wh = ckb_blake2b256(&empty);
    let before = build_account_data(&wh, &ROOT_ID, NOW + ONE_YEAR, &listed, &listed, b"alice");
    let after = build_account_data(&wh, &ROOT_ID, NOW + ONE_YEAR, &s, &s, b"alice");
    let nc = name_cell(&e, NAME_CAP);
    let name_in = e.ctx.create_cell(nc.clone(), Bytes::from(before));
    let offer_in = e.ctx.create_cell(plain(OFFER_CAP, &sale), Bytes::new());
    let mut inputs = vec![input(name_in), input(offer_in)];
    let mut outputs = vec![nc];
    let mut data = vec![Bytes::from(after)];
    if seller_input {
        let cell = e.ctx.create_cell(plain(PLATE, &slock), Bytes::new());
        inputs.push(input(cell));
        outputs.push(plain(PLATE + TOP_UP, &slock));
        data.push(Bytes::new());
    }
    let funds = e.ctx.create_cell(plain(FUNDS, &e.stranger), Bytes::new());
    inputs.push(input(funds));
    // The taker even keeps the offer cell's deposit.
    outputs.push(plain(FUNDS + OFFER_CAP - TOP_UP - TX_FEE, &e.stranger));
    data.push(Bytes::new());
    let n = inputs.len();
    let tx = TransactionBuilder::default()
        .inputs(inputs)
        .outputs(outputs)
        .outputs_data(data.pack())
        .cell_deps(deps)
        .witnesses(witnesses_for(vec![wit(Some(Bytes::from_static(b"transfer")), Some(empty))], n))
        .build();
    let tx = e.ctx.complete_tx(tx);
    e.ctx.verify_tx(&tx, MAX_CYCLES).map_err(|x| format!("{x:?}"))
}

/// The stranger registers `alice` for themselves while an offer by a seller under `seller`
/// is spent in the same transaction with a cell under the seller's lock present: a
/// cancellation, as far as the sale lock is told. Pays the seller `to_seller` (nothing when
/// zero) and the treasury `treasury_out` in one output.
fn register_beside_an_offer(seller: Owner, to_seller: u64, treasury_out: u64) -> Result<u64, String> {
    let mut e = env();
    let (slock, _, deps) = lock_of(&mut e, seller, OWNER);
    let mut args = slock.calc_script_hash().raw_data().to_vec();
    args.extend_from_slice(&PRICE.to_le_bytes());
    let sale = e.ctx.build_script(&e.sale_op, Bytes::from(args)).expect("sale lock");
    let s = id20(&e.stranger);
    let empty = Bytes::new();
    let wh = ckb_blake2b256(&empty);
    let label: &[u8] = b"alice";
    let x = account_id(label);
    let zero = [0u8; OWNER_HASH_LEN];
    let root_before = build_account_data(&wh, &ROOT_ID, 0, &zero, &zero, b"");
    let root_after = build_account_data(&wh, &x, 0, &zero, &zero, b"");
    let name = build_account_data(&wh, &ROOT_ID, NOW + ONE_YEAR, &s, &s, label);
    let nc = name_cell(&e, NAME_CAP);
    let root_in = e.ctx.create_cell(nc.clone(), Bytes::from(root_before));
    let secret = [0x77u8; SECRET_LEN];
    let commit = commitment(&e.ns, label, &s, &secret);
    let commit_in = e.ctx.create_cell(plain(PLATE, &e.stranger), Bytes::from(commit.to_vec()));
    let header = HeaderBuilder::default().timestamp(HEADER_TS_MS.pack()).build();
    e.ctx.insert_header(header.clone());
    e.ctx.link_cell_with_block(commit_in.clone(), header.hash(), 0);
    let offer_in = e.ctx.create_cell(plain(OFFER_CAP, &sale), Bytes::new());
    let seller_in = e.ctx.create_cell(plain(PLATE, &slock), Bytes::new());
    let funds = e.ctx.create_cell(plain(FUNDS, &e.stranger), Bytes::new());
    let inputs = vec![
        input(root_in),
        CellInput::new_builder()
            .since((0xC000_0000_0000_0000u64 | COMMIT_MIN_DELAY).pack())
            .previous_output(commit_in)
            .build(),
        input(offer_in),
        input(seller_in),
        input(funds),
    ];
    let mut outputs = vec![nc.clone(), nc, plain(treasury_out, &e.treasury), plain(PLATE + TOP_UP, &slock)];
    let mut data = vec![Bytes::from(root_after), Bytes::from(name), Bytes::new(), Bytes::new()];
    if to_seller > 0 {
        outputs.push(plain(to_seller, &slock));
        data.push(Bytes::new());
    }
    outputs.push(plain(FUNDS + PLATE + OFFER_CAP - NAME_CAP - treasury_out - TOP_UP - to_seller - TX_FEE, &e.stranger));
    data.push(Bytes::new());
    let n = inputs.len().max(outputs.len());
    let witnesses = witnesses_for(
        vec![
            wit(Some(Bytes::from_static(b"register")), Some(empty.clone())),
            wit(Some(Bytes::from(secret.to_vec())), Some(empty)),
        ],
        n,
    );
    let tx = TransactionBuilder::default()
        .inputs(inputs)
        .outputs(outputs)
        .outputs_data(data.pack())
        .cell_deps(deps)
        .header_dep(header.hash())
        .witnesses(witnesses)
        .build();
    let tx = e.ctx.complete_tx(tx);
    e.ctx.verify_tx(&tx, MAX_CYCLES).map_err(|x| format!("{x:?}"))
}

/// cross_contract.rs's F-9 transaction: renew `alice`, spend an offer, one treasury output.
/// The offer's sale lock is named under `ht`. `Type` is how every listing is made and what
/// `SALE_LOCK_CODE_HASH` is; a data hash type names the same binary by its data hash.
fn renew_and_buy(ht: ScriptHashType, treasury_out: u64) -> Result<u64, String> {
    let mut e = env();
    let (seller, _, _) = lock_of(&mut e, Owner::Plain, MANAGER);
    let (owner, _, _) = lock_of(&mut e, Owner::Plain, OWNER);
    let mut args = seller.calc_script_hash().raw_data().to_vec();
    args.extend_from_slice(&PRICE.to_le_bytes());
    let sale = e.ctx.build_script_with_hash_type(&e.sale_op, ht, Bytes::from(args)).expect("sale lock");
    let o = id20(&owner);
    let empty = Bytes::new();
    let wh = ckb_blake2b256(&empty);
    let before = build_account_data(&wh, &ROOT_ID, NOW + ONE_YEAR, &o, &o, b"alice");
    let after = build_account_data(&wh, &ROOT_ID, NOW + 2 * ONE_YEAR, &o, &o, b"alice");
    let nc = name_cell(&e, NAME_CAP);
    let name_in = e.ctx.create_cell(nc.clone(), Bytes::from(before));
    let offer_in = e.ctx.create_cell(plain(OFFER_CAP, &sale), Bytes::new());
    let funds = e.ctx.create_cell(plain(FUNDS * 10, &e.stranger), Bytes::new());
    let outputs = vec![nc, plain(TO_SELLER, &seller), plain(treasury_out, &e.treasury)];
    let data = vec![Bytes::from(after), Bytes::new(), Bytes::new()];
    let tx = TransactionBuilder::default()
        .inputs(vec![input(name_in), input(offer_in), input(funds)])
        .outputs(outputs)
        .outputs_data(data.pack())
        .witnesses(witnesses_for(vec![wit(Some(Bytes::from_static(b"renew")), Some(empty))], 3))
        .build();
    let tx = e.ctx.complete_tx(tx);
    e.ctx.verify_tx(&tx, MAX_CYCLES).map_err(|x| format!("{x:?}"))
}

/// A buyer pays in full and spends an offer under the sale lock named by `spent`, while
/// the name records the sale lock named by `listed` as its owner.
fn buy_with(listed: ScriptHashType, spent: ScriptHashType) -> Result<u64, String> {
    let mut e = env();
    let (seller, _, _) = lock_of(&mut e, Owner::Plain, MANAGER);
    let mut args = seller.calc_script_hash().raw_data().to_vec();
    args.extend_from_slice(&PRICE.to_le_bytes());
    let args = Bytes::from(args);
    let real = e.ctx.build_script_with_hash_type(&e.sale_op, listed, args.clone()).expect("listed");
    let look = e.ctx.build_script_with_hash_type(&e.sale_op, spent, args).expect("spent");
    let owner = id20(&real);
    let s = id20(&e.stranger);
    let empty = Bytes::new();
    let wh = ckb_blake2b256(&empty);
    let before = build_account_data(&wh, &ROOT_ID, NOW + ONE_YEAR, &owner, &owner, b"alice");
    let after = build_account_data(&wh, &ROOT_ID, NOW + ONE_YEAR, &s, &s, b"alice");
    let nc = name_cell(&e, NAME_CAP);
    let name_in = e.ctx.create_cell(nc.clone(), Bytes::from(before));
    let offer_in = e.ctx.create_cell(plain(OFFER_CAP, &look), Bytes::new());
    let funds = e.ctx.create_cell(plain(FUNDS * 10, &e.stranger), Bytes::new());
    let outputs = vec![nc, plain(TO_SELLER, &seller), plain(sale_fee(PRICE), &e.treasury)];
    let data = vec![Bytes::from(after), Bytes::new(), Bytes::new()];
    let tx = TransactionBuilder::default()
        .inputs(vec![input(name_in), input(offer_in), input(funds)])
        .outputs(outputs)
        .outputs_data(data.pack())
        .witnesses(witnesses_for(vec![wit(Some(Bytes::from_static(b"transfer")), Some(empty))], 3))
        .build();
    let tx = e.ctx.complete_tx(tx);
    e.ctx.verify_tx(&tx, MAX_CYCLES).map_err(|x| format!("{x:?}"))
}

/// The seller spends their own offer, named under `ht`, with a cell of theirs, and takes
/// the deposit back along with their change: a cancellation as the SDK builds it, where
/// the seller's lock ends up with more than it put in.
fn seller_cancels(ht: ScriptHashType) -> Result<u64, String> {
    let mut e = env();
    let (seller, _, _) = lock_of(&mut e, Owner::Plain, OWNER);
    let mut args = seller.calc_script_hash().raw_data().to_vec();
    args.extend_from_slice(&PRICE.to_le_bytes());
    let sale = e.ctx.build_script_with_hash_type(&e.sale_op, ht, Bytes::from(args)).expect("sale lock");
    let offer_in = e.ctx.create_cell(plain(OFFER_CAP, &sale), Bytes::new());
    let own = e.ctx.create_cell(plain(PLATE, &seller), Bytes::new());
    let tx = TransactionBuilder::default()
        .inputs(vec![input(offer_in), input(own)])
        .output(plain(PLATE + OFFER_CAP - TX_FEE, &seller))
        .output_data(Bytes::new().pack())
        .witnesses(witnesses_for(vec![], 2))
        .build();
    let tx = e.ctx.complete_tx(tx);
    e.ctx.verify_tx(&tx, MAX_CYCLES).map_err(|x| format!("{x:?}"))
}

/// A name held as a deed (decision 0036): its owner is the proxy lock over a Spore, and
/// the holder acts through the proxy cell, which the SDK spends and hands back unchanged
/// (`tx.addOutput(p.cellOutput, p.outputData)` in client.ts). The proxy lock is modelled by
/// a plain lock; what matters here is that its cell comes back exactly as it went in.
fn deed_holder_transfers() -> Result<u64, String> {
    let mut e = env();
    let proxy = e.ctx.build_script(&e.plain_op, Bytes::from_static(b"input-type-proxy-lock")).expect("proxy");
    let (holder, _, _) = lock_of(&mut e, Owner::Plain, HOLDER);
    let (p, h) = (id20(&proxy), id20(&holder));
    let empty = Bytes::new();
    let wh = ckb_blake2b256(&empty);
    let before = build_account_data(&wh, &ROOT_ID, NOW + ONE_YEAR, &p, &p, b"alice");
    let after = build_account_data(&wh, &ROOT_ID, NOW + ONE_YEAR, &h, &h, b"alice");
    let nc = name_cell(&e, NAME_CAP);
    let name_in = e.ctx.create_cell(nc.clone(), Bytes::from(before));
    let proxy_data = Bytes::from(vec![0x5A; 60]);
    let proxy_in = e.ctx.create_cell(plain(PROXY_CAP, &proxy), proxy_data.clone());
    let own = e.ctx.create_cell(plain(PLATE, &holder), Bytes::new());
    let tx = TransactionBuilder::default()
        .inputs(vec![input(name_in), input(proxy_in), input(own)])
        .outputs(vec![nc, plain(PROXY_CAP, &proxy), plain(PLATE - TX_FEE, &holder)])
        .outputs_data(vec![Bytes::from(after), proxy_data, Bytes::new()].pack())
        .witnesses(witnesses_for(vec![wit(Some(Bytes::from_static(b"transfer")), Some(empty))], 3))
        .build();
    let tx = e.ctx.complete_tx(tx);
    e.ctx.verify_tx(&tx, MAX_CYCLES).map_err(|x| format!("{x:?}"))
}

/// Run `run` for every lock on the list, print every answer, then insist each was refused
/// with `code`, so a run before the fix shows all six rather than stopping at the first.
fn refused_for_every_listed_lock(what: &str, code: i32, run: impl Fn(Listed) -> Result<u64, String>) {
    let results: Vec<(Listed, Result<u64, String>)> = LISTED
        .iter()
        .map(|&l| {
            let r = run(l);
            show(&format!("{what} [{l:?}]"), &r);
            (l, r)
        })
        .collect();
    for (l, r) in &results {
        assert_code(r, code, &format!("{what} [{l:?}]"));
    }
}

// --- the list is the chain ----------------------------------------------------------------

#[test]
fn the_listed_code_hashes_are_the_deployed_type_ids() {
    for l in LISTED {
        assert_eq!(
            tests::type_id_hash(l.type_id_args()),
            l.listed_as(),
            "{l:?}: the contract lists a code hash the chain's code cell does not have"
        );
    }
    // Every type id the contracts carry is exercised above. The rest of the lists are the
    // same binaries by their data hash, six of them, which take the same path in
    // `lets_anyone_spend` (cells-core's own tests loop over every entry).
    let by_data = 4 + 2;
    assert_eq!(ANYONE_CAN_PAY_CODE_HASHES.len() + OMNILOCK_CODE_HASHES.len(), LISTED.len() + by_data);
}

// --- owner consent: what a stranger can no longer do ---------------------------------------

#[test]
fn a_stranger_cannot_transfer_a_name_whose_owner_lock_anyone_can_spend() {
    refused_for_every_listed_lock("transfer, stranger tops up the owner's cell", 29, |l| {
        stranger_acts(Owner::Listed(l), None, b"transfer", Plate::Owner)
    });
}

#[test]
fn a_stranger_cannot_rewrite_the_records_of_such_a_name() {
    refused_for_every_listed_lock("edit_records, stranger tops up the owner's cell", 29, |l| {
        stranger_acts(Owner::Listed(l), None, b"edit_records", Plate::Owner)
    });
}

#[test]
fn a_stranger_cannot_make_themselves_the_manager_of_such_a_name() {
    refused_for_every_listed_lock("edit_manager, stranger tops up the owner's cell", 29, |l| {
        stranger_acts(Owner::Listed(l), None, b"edit_manager", Plate::Owner)
    });
}

#[test]
fn a_manager_lock_anyone_can_spend_does_not_let_a_stranger_edit() {
    refused_for_every_listed_lock("edit_records, stranger tops up the manager's cell", 29, |l| {
        stranger_acts(Owner::Plain, Some(Owner::Listed(l)), b"edit_records", Plate::Manager)
    });
}

#[test]
fn a_stranger_cannot_mint_a_sub_name_under_such_a_parent() {
    refused_for_every_listed_lock("register shop.alice, stranger tops up the parent owner's cell", 29, |l| {
        register_sub_name(Owner::Listed(l), Some(TOP_UP))
    });
}

#[test]
fn a_stranger_cannot_renew_a_sub_name_of_such_a_parent() {
    refused_for_every_listed_lock("renew shop.alice, stranger tops up the parent owner's cell", 29, |l| {
        renew_sub_name(Owner::Listed(l), Some(TOP_UP))
    });
}

#[test]
fn a_commit_held_under_such_a_lock_is_not_the_owners() {
    refused_for_every_listed_lock("register alice, commit parked under the owner's lock", 47, |l| {
        stranger_lands_registration(Owner::Listed(l))
    });
}

#[test]
fn a_stranger_cannot_take_a_name_listed_by_such_a_seller_unpaid() {
    refused_for_every_listed_lock("take a listed name, stranger tops up the seller's cell, nothing paid", 3, |l| {
        take_listed_name(Owner::Listed(l), true)
    });
}

/// The other half of the seller rule, in `account-cell-type`: an offer whose seller is
/// present owes the treasury nothing (a cancellation), and "present" must mean the same
/// there as in the sale lock. If the sale lock stopped counting such a seller and this
/// side did not, the sale's fee would again be answered by the registration's (F-9).
#[test]
fn a_seller_input_anyone_can_spend_is_not_a_cancellation_and_the_sale_owes_its_fee() {
    refused_for_every_listed_lock("register beside a listed seller's offer, registration fee only", 42, |l| {
        register_beside_an_offer(Owner::Listed(l), TO_SELLER, registration_fee(b"alice", 1))
    });
    // Both fees paid, the same transaction is a sale beside a registration and goes through.
    for l in LISTED {
        let res = register_beside_an_offer(Owner::Listed(l), TO_SELLER, registration_fee(b"alice", 1) + sale_fee(PRICE));
        show(&format!("register beside a listed seller's offer, both fees [{l:?}]"), &res);
        assert!(res.is_ok(), "{l:?}: a sale beside a registration paying both fees must pass, got {res:?}");
    }
}

// --- owner consent: the controls ---------------------------------------------------------------

#[test]
fn a_secp256k1_owner_that_signs_can_transfer() {
    let res = stranger_acts(Owner::SecpSigned, None, b"transfer", Plate::Owner);
    show("secp256k1 owner, signed, transfer", &res);
    assert!(res.is_ok(), "the harness must be able to pass a signed owner, got {res:?}");
}

#[test]
fn a_secp256k1_owner_without_its_signature_is_refused_by_its_lock() {
    let res = stranger_acts(Owner::SecpUnsigned, None, b"transfer", Plate::Owner);
    show("secp256k1 owner, no signature, transfer", &res);
    let e = res.expect_err("an unsigned secp256k1 input must not unlock");
    assert!(e.contains("Inputs[1].Lock"), "the refusal must come from the owner's lock, got {e}");
}

#[test]
fn no_input_under_the_owner_is_unauthorized() {
    let res = stranger_acts(Owner::Listed(Listed::AnyoneCanPayMainnet), None, b"transfer", Plate::None);
    show("anyone-can-pay owner, no owner input, transfer", &res);
    assert_code(&res, 29, "a transfer with no input under the owner's lock");
}

/// Omnilock is on the list only with its anyone-can-pay flag. Without it, it is an
/// ordinary key (the flags CCC's own signers write are zero), and its owner acts as before.
#[test]
fn an_omnilock_owner_without_the_flag_still_acts() {
    for action in [&b"transfer"[..], b"edit_records", b"edit_manager"] {
        let res = stranger_acts(Owner::Omnilock, None, action, Plate::Owner);
        show(&format!("omnilock owner without the flag, {}", String::from_utf8_lossy(action)), &res);
        assert!(res.is_ok(), "an Omnilock owner without the flag must still act, got {res:?}");
    }
}

#[test]
fn a_delegated_manager_that_signs_can_still_edit() {
    let res = stranger_acts(Owner::Listed(Listed::AnyoneCanPayMainnet), Some(Owner::Plain), b"edit_records", Plate::Manager);
    show("anyone-can-pay owner, ordinary manager present, edit_records", &res);
    assert!(res.is_ok(), "a manager under an ordinary lock must still edit records, got {res:?}");
}

/// The shapes the SDK builds, where the party giving consent pays nothing: a parent owner
/// co-signing a sub-name, a deed's proxy cell, a seller cancelling. A rule that asked the
/// consenting lock to lose capacity would refuse every one of them.
#[test]
fn a_parent_owner_cosigning_for_nothing_still_authorizes_a_sub_name() {
    let res = register_sub_name(Owner::Plain, Some(0));
    show("register shop.alice, parent owner's cell handed back at its exact capacity", &res);
    assert!(res.is_ok(), "the SDK's co-sign must still authorize a sub-name, got {res:?}");
    let res = renew_sub_name(Owner::Plain, Some(0));
    show("renew shop.alice, parent owner's cell handed back at its exact capacity", &res);
    assert!(res.is_ok(), "the SDK's co-sign must still authorize a sub-name's renewal, got {res:?}");
}

#[test]
fn a_deed_proxy_cell_handed_back_unchanged_still_authorizes_a_transfer() {
    let res = deed_holder_transfers();
    show("deed holder transfers through the proxy cell, handed back unchanged", &res);
    assert!(res.is_ok(), "a deed's holder must still act through the proxy cell, got {res:?}");
}

#[test]
fn a_seller_who_cancels_takes_the_deposit_back() {
    let res = seller_cancels(ScriptHashType::Type);
    show("seller cancels, deposit back with the change", &res);
    assert!(res.is_ok(), "a seller must still be able to cancel, got {res:?}");
}

/// Named by the comment on `owed_by_sales` in account-cell-type, which has promised it
/// since 2026-09-14. A cancellation beside a registration owes the treasury nothing more.
#[test]
fn a_cancellation_beside_a_registration_owes_no_sale_fee() {
    let res = register_beside_an_offer(Owner::Plain, 0, registration_fee(b"alice", 1));
    show("register beside the seller's own cancellation, registration fee only", &res);
    assert!(res.is_ok(), "a cancellation is not a sale and owes no fee, got {res:?}");
}

/// The list names the locks that are deployed. A lock of the same kind that it does not
/// know still counts as its owner's consent, and nothing inside the contracts can know
/// every lock: the SDK has to refuse to hand a name to one. Open by design, like F-2, and
/// ignored so the suite stays green while the limit stays named.
#[test]
#[ignore = "open by design: an anyone-can-pay lock the list does not know still counts as its owner's consent"]
fn an_anyone_can_pay_lock_the_list_does_not_know_still_counts() {
    let res = stranger_acts(Owner::Unlisted, None, b"transfer", Plate::Owner);
    show("unlisted anyone-can-pay owner, stranger tops up, transfer", &res);
    assert!(res.is_err(), "a stranger took a name from a lock the list does not know: {res:?}");
}

// --- offers by data hash --------------------------------------------------------------------------

#[test]
fn an_offer_named_by_data_hash_no_longer_leaks_the_sale_fee() {
    for ht in [ScriptHashType::Data1, ScriptHashType::Data2] {
        let res = renew_and_buy(ht, registration_fee(b"alice", 1));
        show(&format!("renew + buy, sale lock {ht:?}, renewal fee only"), &res);
        assert_code(&res, 5, &format!("{ht:?}: one fee for a renewal and a sale"));
    }
}

#[test]
fn an_offer_named_by_data_hash_cannot_be_bought() {
    for ht in [ScriptHashType::Data1, ScriptHashType::Data2] {
        let res = renew_and_buy(ht, registration_fee(b"alice", 1) + sale_fee(PRICE));
        show(&format!("renew + buy, sale lock {ht:?}, both fees"), &res);
        assert_code(&res, 5, &format!("{ht:?}: an offer by data hash is not for sale"));
    }
}

#[test]
fn an_offer_by_type_id_still_sells_and_owes_both_fees() {
    let both = renew_and_buy(ScriptHashType::Type, registration_fee(b"alice", 1) + sale_fee(PRICE));
    show("renew + buy, sale lock Type, both fees", &both);
    assert!(both.is_ok(), "an honest batch must pass, got {both:?}");
    let short = renew_and_buy(ScriptHashType::Type, registration_fee(b"alice", 1));
    show("renew + buy, sale lock Type, renewal fee only", &short);
    assert_code(&short, 42, "one fee for a renewal and a sale");
}

#[test]
fn a_seller_can_still_take_back_an_offer_named_by_data_hash() {
    for ht in [ScriptHashType::Data1, ScriptHashType::Data2] {
        let res = seller_cancels(ht);
        show(&format!("seller cancels an offer named by {ht:?}"), &res);
        assert!(res.is_ok(), "{ht:?}: the seller must still be able to reclaim it, got {res:?}");
    }
}

#[test]
fn a_look_alike_of_the_listing_does_not_authorize_the_transfer() {
    let honest = buy_with(ScriptHashType::Type, ScriptHashType::Type);
    show("listed Type, spent Type (the listing itself), paid", &honest);
    assert!(honest.is_ok(), "buying the real listing must pass, got {honest:?}");
    for spent in [ScriptHashType::Data1, ScriptHashType::Data2] {
        let res = buy_with(ScriptHashType::Type, spent);
        show(&format!("listed Type, spent {spent:?} look-alike, paid"), &res);
        assert!(res.is_err(), "{spent:?}: a look-alike of the listing must not take the name, got {res:?}");
    }
}
