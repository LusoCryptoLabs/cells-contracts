//! Print the lock hash of the treasury lock the integration tests build.
//!
//! `TREASURY_LOCK_HASH` is compiled into the contract, and a lock hash is derived
//! from the lock's own code and args, so the mock VM cannot produce a cell that
//! hashes to the real treasury address. `make test` therefore builds a separate
//! contract binary with `CELLS_TREASURY_LOCK_HASH` set to whatever this prints.
//!
//! It is computed here rather than pasted into the Makefile so that bumping
//! ckb-testtool (which would change the always-success binary, and with it the
//! hash) keeps working instead of failing with a mismatch nobody can place.

use ckb_testtool::builtin::ALWAYS_SUCCESS;
use ckb_testtool::ckb_types::{bytes::Bytes, core::ScriptHashType, prelude::*};
use ckb_testtool::context::Context;

/// Must match `lock_args(L::Treasury)` in tests/account_cell.rs.
const TREASURY_ARGS: &[u8] = b"treasury";

fn main() {
    let mut ctx = Context::default();
    let out_point = ctx.deploy_cell(ALWAYS_SUCCESS.clone());
    // Data1, not the Type that `build_script` defaults to. A Type script's code hash
    // is the deployed cell's type-id hash, whose args ckb-testtool fills with random
    // bytes per Context, so a Type-hashed lock hashes differently on every run and no
    // compile-time constant could ever match it. The data hash of always-success is
    // fixed by the crate version, so this one is reproducible. Nothing is lost: an
    // output's lock is never executed, so the treasury lock needs no cell dep.
    let script = ctx
        .build_script_with_hash_type(&out_point, ScriptHashType::Data1, Bytes::from_static(TREASURY_ARGS))
        .expect("build the treasury lock");
    // Bare hex, no 0x and no trailing newline: the form cells-core's parser expects
    // and the Makefile can hand straight to the compiler.
    let mut hex = String::with_capacity(64);
    for b in script.calc_script_hash().as_slice() {
        hex.push_str(&format!("{b:02x}"));
    }
    print!("{hex}");
}
