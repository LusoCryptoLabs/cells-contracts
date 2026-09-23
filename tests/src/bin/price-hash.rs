//! Print the type-script hash of the price cell the integration tests present.
//!
//! `PRICE_CELL_TYPE_HASH` is compiled into `account-cell-type` (decision 0014), so
//! the test build needs a hash it can be handed, and the tests need a cell that hashes
//! to it. As with the treasury (see treasury-hash.rs), the script is Data1-hashed with
//! fixed args, because a Type-hashed script's code hash is a per-Context random
//! type-id that no compile-time constant could match.
//!
//! The code hash is the data hash of the `price-cell-type` binary in `CELLS_PRICE_DIR`
//! (the normal release build; `make test` builds it first). The tests deploy that same
//! file, so `ctx.build_script_with_hash_type(.., Data1, b"price")` hashes identically.

use ckb_testtool::ckb_types::{
    bytes::Bytes,
    core::ScriptHashType,
    packed::{CellOutput, Script},
    prelude::*,
};
use std::{env, fs};

/// Must match the args the tests give the price cell's type script.
const PRICE_ARGS: &[u8] = b"price";

fn main() {
    let dir = env::var("CELLS_PRICE_DIR")
        .unwrap_or_else(|_| "../target/riscv64imac-unknown-none-elf/release".to_string());
    let path = format!("{dir}/price-cell-type");
    let bin = fs::read(&path).unwrap_or_else(|e| {
        panic!("failed to read {path}: {e}\nbuild it first: `make build` (from contracts/)")
    });
    let script = Script::new_builder()
        .code_hash(CellOutput::calc_data_hash(&bin))
        .hash_type(ScriptHashType::Data1.into())
        .args(Bytes::from_static(PRICE_ARGS).pack())
        .build();
    // Bare hex, no 0x, no newline: what cells-core's parser and the Makefile expect.
    let mut hex = String::with_capacity(64);
    for b in script.calc_script_hash().as_slice() {
        hex.push_str(&format!("{b:02x}"));
    }
    print!("{hex}");
}
