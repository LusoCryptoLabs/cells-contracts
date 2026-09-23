//! Print the **code** hash the integration tests will give the sale lock.
//!
//! `SALE_LOCK_CODE_HASH` is compiled into `account-cell-type`, which uses it to recognise
//! an offer being spent in the same transaction and add what that sale owes the treasury
//! on top of its own fee (F-9). On chain that code hash is the sale lock's type id, fixed
//! for the life of the deployment because upgrades are in place.
//!
//! In a test it cannot be. `Context::build_script` makes a Type script whose code hash is
//! the deployed cell's type-id hash, and ckb-testtool fills those args with random bytes
//! per `Context`, so the same binary hashes differently on every run. This prints the
//! **data** hash instead, which is fixed by the binary, and the tests build their sale
//! locks with `ScriptHashType::Data1` so the two agree. Exactly the trick
//! `treasury-hash.rs` uses, for exactly the same reason.
//!
//! `make test` bakes whatever this prints into the test-only build. The deployable
//! artifact is never touched.

use ckb_testtool::ckb_types::prelude::*;
use ckb_testtool::context::Context;
use tests::Loader;

fn main() {
    let mut ctx = Context::default();
    let out_point = ctx.deploy_cell(Loader::default().load_binary("sale-lock"));
    let cell = ctx.cells.get(&out_point).expect("the cell was just deployed");
    // The data hash of the binary: what a Data1 script's code hash is.
    let hash = ckb_testtool::ckb_types::packed::CellOutput::calc_data_hash(&cell.1);
    let mut hex = String::with_capacity(64);
    for b in hash.as_slice() {
        hex.push_str(&format!("{b:02x}"));
    }
    print!("{hex}");
}
