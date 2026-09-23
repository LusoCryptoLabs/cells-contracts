//! Test support: locate the compiled on-chain binaries.
//!
//! `make build` produces them under the workspace target dir. Override the
//! location with `CELLS_CONTRACTS_DIR` if you build elsewhere.
use ckb_testtool::ckb_types::bytes::Bytes;
use std::{env, fs, path::PathBuf};

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
