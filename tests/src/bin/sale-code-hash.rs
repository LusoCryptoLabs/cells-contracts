//! Print the **code** hash the integration tests will give the sale lock.
//!
//! `SALE_LOCK_CODE_HASH` is compiled into `account-cell-type`, which uses it to recognise
//! an offer being spent in the same transaction and add what that sale owes the treasury
//! on top of its own fee (F-9). On chain that code hash is the sale lock's type id, fixed
//! for the life of the deployment because upgrades are in place.
//!
//! The harness does the same: `tests::deploy_sale_lock` creates the sale lock's code cell
//! under fixed type-id args, and the tests name it by `hash_type: type`. So this prints
//! the type id of those args. It does not depend on the binary, which is why `make test`
//! needs one build of the contracts and not two.
//!
//! Until 2026-09-27 this printed the binary's data hash and the tests used
//! `ScriptHashType::Data1`, because `Context::build_script` draws random type-id args.
//! The chain was the other way round, so the harness never tested an offer the way the
//! chain names one, and could not test a rule about the hash type at all.
//!
//! `make test` bakes whatever this prints into the test-only build. The deployable
//! artifact is never touched.

fn main() {
    let mut hex = String::with_capacity(64);
    for b in tests::type_id_hash(tests::SALE_TYPE_ID_ARGS) {
        hex.push_str(&format!("{b:02x}"));
    }
    print!("{hex}");
}
