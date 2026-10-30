# Cells contracts

[![make test and reproduce mainnet](https://github.com/LusoCryptoLabs/cells-contracts/actions/workflows/test.yml/badge.svg)](https://github.com/LusoCryptoLabs/cells-contracts/actions/workflows/test.yml)

The on-chain half of [cellula.id](https://cellula.id): four Nervos CKB scripts and the
crate they share, which together keep `.cell` names unique, owned, priced and sellable.
Live on CKB mainnet since 2026-09-21.

| | what it guards | lines |
|---|---|---|
| `account-cell-type` | every name: the ring that keeps them unique, who may edit, transfer, renew or recycle, and what a registration must pay | 1,155 |
| `account-lock` | nothing, on purpose. It always succeeds, so the type script above is the only guardian | 25 |
| `sale-lock` | a listing: the buyer pays the seller and the protocol in one transaction, or nothing moves | 246 |
| `price-cell-type` | one cell holding a discount factor, bounded by its own rules | 162 |
| `cells-core` | the layout, the ring arithmetic and the fee schedule, shared by all four | 1,685 |

## Check that this is what runs

The binaries on mainnet reproduce from this source, with one toolchain and three values.
The values are compiled in and all three are public, since they end up inside a binary
anyone can read off the chain:

```sh
CARGO_TARGET_DIR=target/mainnet \
CELLS_TREASURY_LOCK_HASH=57d926a44d83fc13b21ce037b1e31f4223e3c867cfa3f60e1324d5bfd5cd742d \
CELLS_SALE_LOCK_CODE_HASH=086c8f4e9d4272e3dfbaca399792f730e6604591e87931ee6d67047a3c900879 \
CELLS_PRICE_CELL_TYPE_HASH=3f1c9a47d666bd0b5f9a4b2b3afd7c20216280dbcfaddd13748780cdfcbb7586 \
make build
```

The CKB hash of each result, against the code cell on chain, checked 2026-10-29
(`account-cell-type` and `sale-lock` since the upgrade of 2026-09-28, docs/SECURITY.md):

| | data hash on chain | bytes |
|---|---|---|
| `account-cell-type` | `0x99ea60a4369ed3d596338b66d6818710a1d047758f478dd854dd814b786aa088` | 44,016 |
| `account-lock` | `0xa46c19f2262abc0d0db0de3952b7477792b36b392645e0f60e74637ae3e3f13b` | 1,152 |
| `sale-lock` | `0x57cdfaa46bc62012315f7c64719f01b43accb66bfc091183a751d59309da3068` | 18,280 |
| `price-cell-type` | `0x238e74e1d2d5bf8f06f9f4b0bb352c2addd531351a45cfeddf3ff5f6f5662342` | 22,984 |

`https://cellula.id/api/verify` makes the same comparison live and answers `verified:
true`, or not. Without the three values, `make build` produces the test-network binary and
the hashes will not match; that is not a failed verification.

**The toolchain is part of the recipe.** `ckb-std` compiles a small C shim for the RISC-V
target, and the mainnet binaries were built with the GNU cross-compiler,
`riscv64-unknown-elf-gcc` 13.2.0 (Ubuntu 24.04's `gcc-riscv64-unknown-elf`), and rustc
1.96.0, which `rust-toolchain.toml` pins. Built with clang instead, `account-cell-type`,
`sale-lock` and `price-cell-type` come out 24, 80 and 24 bytes different and hash
differently; they behave the same, and the difference is the compiler, not the source.
`cc-rs` picks gcc when it is on the path and clang otherwise, without saying which. The
`reproduce-mainnet` job in CI does this build with gcc on every push and compares the four
hashes with the ones above, so the badge at the top is that check as well as the tests.

One more thing is baked in, and it is nobody's choice: with overflow checks on, every
checked arithmetic carries the source path of the crate it sits in, and for the crates
from the registry that path starts at the build machine's cargo home, which was
`/root/.cargo`. Built from another home the three larger binaries come out a few dozen
bytes different. The Makefile remaps your cargo home to that one, so `make build` agrees
from any machine; a future upgrade should be built with a neutral prefix instead, so this
stops mattering.

## Run the tests

```sh
make test
```

223 tests: the shared crate's own, and a harness that runs the real scripts in `ckb-testtool`
against every action, the properties over the ring and the fees, a fuzz over every parser,
and the cases where two of the contracts meet in one transaction. Three more are marked
`ignore` on purpose: each is a reproduction, not a guard, and fails, which is the point.
One builds the transaction that finding F-2 in [docs/SECURITY.md](docs/SECURITY.md)
describes, two namespaces sharing one treasury and one fee answering both; the rule that
closes it is one treasury per namespace, and mainnet has one. One shows that an
anyone-can-pay lock missing from the contracts' list still counts as its owner's consent,
a limit by design. One replays the listing hole of 2026-09-27 against the builds that ran
on mainnet until the upgrade of 2026-09-28 closed it. A closed-loop test against our
off-chain registrar is not here, because the registrar is not.

You need the Rust in `rust-toolchain.toml` and a C compiler that targets RISC-V, which
`ckb-std` wants: `gcc-riscv64-unknown-elf` to reproduce the mainnet bytes, or clang for the
tests alone, with `CC_riscv64imac_unknown_none_elf=clang AR_riscv64imac_unknown_none_elf=llvm-ar`
in the environment, which is what the `make test` job in CI does. Do not run a bare `cargo test` inside `tests/`: the treasury hash is
compiled in and the mock VM cannot make a cell that hashes to the real one, so `make test`
builds a test-treasury variant first and points the harness at it.

## Read

- [docs/SPEC.md](docs/SPEC.md), what the contracts enforce, in the words of the layout and the actions.
- [docs/SECURITY.md](docs/SECURITY.md), every finding from eleven review passes, what was fixed and what is open, with the journal of the first nine beside it.
- [docs/TRUST.md](docs/TRUST.md), who can change what, and how to check.
- [docs/decisions/](docs/decisions/), why each rule is the way it is.

To build on the names rather than on the contracts: [cellula.id/developers](https://cellula.id/developers)
has the HTTP resolver, one call for everything a name publishes, and the SDK is
[`cellula-sdk`](https://www.npmjs.com/package/cellula-sdk) on npm. The application that runs
the site is not in this repository.

MIT.
