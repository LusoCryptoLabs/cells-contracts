//! Test support: locate the compiled on-chain binaries.
//!
//! `make build` produces them under the workspace target dir. Override the
//! location with `CELLS_CONTRACTS_DIR` if you build elsewhere.
use ckb_testtool::ckb_chain_spec::consensus::TYPE_ID_CODE_HASH;
use ckb_testtool::ckb_types::{
    bytes::Bytes,
    core::{Capacity, ScriptHashType},
    packed::{CellOutput, OutPoint, Script},
    prelude::*,
};
use ckb_testtool::context::{random_out_point, Context};
use std::{env, fs, path::PathBuf};

/// A type-id script with the given args, the type script every code cell on chain wears.
pub fn type_id_script(args: [u8; 32]) -> Script {
    Script::new_builder()
        .code_hash(TYPE_ID_CODE_HASH.pack())
        .hash_type(ScriptHashType::Type.into())
        .args(Bytes::from(args.to_vec()).pack())
        .build()
}

/// The code hash a script gets when it names that code cell by `hash_type: type`.
pub fn type_id_hash(args: [u8; 32]) -> [u8; 32] {
    let mut h = [0u8; 32];
    h.copy_from_slice(type_id_script(args).calc_script_hash().as_slice());
    h
}

/// Create a code cell under the type-id script with `args`, holding `code`.
///
/// `Context::deploy_cell` draws the type-id args at random for every Context, so a
/// script naming its cell by `hash_type: type` hashes differently on every run and no
/// constant compiled into a contract can match it. Fixing the args fixes the code hash,
/// which is how a contract is found on chain: by type id, whatever its bytes are.
pub fn deploy_under_type_id(ctx: &mut Context, args: [u8; 32], code: Bytes) -> OutPoint {
    let cell = CellOutput::new_builder().type_(Some(type_id_script(args)).pack()).build();
    let size = Capacity::bytes(code.len()).expect("code size");
    let cell = cell.clone().as_builder().capacity(cell.occupied_capacity(size).expect("capacity").pack()).build();
    let out_point = random_out_point();
    ctx.create_cell_with_out_point(out_point.clone(), cell, code);
    out_point
}

/// The type-id args the harness gives the sale lock. `SALE_LOCK_CODE_HASH` is the sale
/// lock's type id on chain, so the test build is compiled with `type_id_hash` of these
/// (src/bin/sale-code-hash.rs prints it) and the tests name the sale lock by
/// `hash_type: type`, as the chain does.
pub const SALE_TYPE_ID_ARGS: [u8; 32] = *b"cells harness: sale-lock type id";

/// The sale lock's code cell, under `SALE_TYPE_ID_ARGS`. `Context::build_script` on the
/// returned out point gives a sale lock by type id; `build_script_with_hash_type` with a
/// data hash type gives the same binary by its data hash, the look-alike.
pub fn deploy_sale_lock(ctx: &mut Context) -> OutPoint {
    deploy_under_type_id(ctx, SALE_TYPE_ID_ARGS, Loader::default().load_binary("sale-lock"))
}

pub struct Loader(PathBuf);

impl Default for Loader {
    fn default() -> Self {
        let dir = env::var("CELLS_CONTRACTS_DIR")
            .unwrap_or_else(|_| "../target/riscv64imac-unknown-none-elf/release".to_string());
        Loader(PathBuf::from(dir))
    }
}

impl Loader {
    /// A loader rooted at an explicit directory, for a binary that must come from
    /// somewhere other than `CELLS_CONTRACTS_DIR`. `price-cell-type` is loaded from
    /// the normal release build, the same file `src/bin/price-hash.rs` hashed, so the
    /// type hash compiled into the test contract and the cell the tests present agree
    /// by construction rather than by two builds happening to be identical.
    pub fn at(dir: impl Into<PathBuf>) -> Self {
        Loader(dir.into())
    }

    pub fn load_binary(&self, name: &str) -> Bytes {
        let mut path = self.0.clone();
        path.push(name);
        let bin = fs::read(&path).unwrap_or_else(|e| {
            panic!(
                "failed to read contract binary {path:?}: {e}\n\
                 build the contracts first: `make build` (from contracts/)"
            )
        });
        Bytes::from(bin)
    }
}
