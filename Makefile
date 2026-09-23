TARGET := riscv64imac-unknown-none-elf
CARGO  := cargo

.PHONY: build check fmt clippy test clean

# Build the on-chain scripts (release, RISC-V).
build:
	$(CARGO) build --release --target $(TARGET)

check:
	$(CARGO) check --release --target $(TARGET)

fmt:
	$(CARGO) fmt --all

clippy:
	$(CARGO) clippy --release --target $(TARGET) -- -D warnings

# Where the test-only build of the contracts goes. A lock hash is derived from the
# lock's own code and args, so the mock VM cannot produce a cell that hashes to the
# real treasury (decision 0009) and the fee check could otherwise only be tested
# failing. The tests therefore run against a binary compiled with the harness's own
# hash, in a directory of its own: `make build` output is never overwritten, so a
# test-flavoured treasury can never be the thing that gets deployed.
TEST_DIR := target/test-treasury

# The price cell (decision 0014) is found by a type-script hash compiled into
# account-cell-type, exactly like the treasury. The tests present a Data1-hashed price
# cell with fixed args, and src/bin/price-hash.rs prints that hash from the normal
# release build of price-cell-type, which is built first so the hash exists to bake.
# The tests load price-cell-type from that same directory (CELLS_PRICE_DIR), so the
# hash compiled in and the cell presented agree by construction.
PRICE_DIR := target/$(TARGET)/release

# Host-target tests: pure cells-core unit tests + ckb-testtool integration.
test:
	$(CARGO) test -p cells-core
	$(CARGO) build --release --target $(TARGET) -p price-cell-type
	CELLS_TREASURY_LOCK_HASH=$$(cd tests && $(CARGO) run --quiet --bin treasury-hash) \
	CELLS_PRICE_CELL_TYPE_HASH=$$(cd tests && $(CARGO) run --quiet --bin price-hash) \
	  $(CARGO) build --release --target $(TARGET) --target-dir $(TEST_DIR)
# Two passes, and the reason is a circle. `account-cell-type` is compiled against the
# sale lock's code hash (F-9), and in a test that hash is the data hash of the sale-lock
# binary the tests will load. That binary is the one in TEST_DIR, compiled with the
# harness's own treasury hash, so its bytes differ from the deployable build and its hash
# with them. So: build TEST_DIR once to produce the sale lock, hash THAT, and build again
# with it. The second pass recompiles sale-lock from identical inputs, so the hash it was
# given stays true.
	CELLS_TREASURY_LOCK_HASH=$$(cd tests && $(CARGO) run --quiet --bin treasury-hash) \
	CELLS_PRICE_CELL_TYPE_HASH=$$(cd tests && $(CARGO) run --quiet --bin price-hash) \
	CELLS_SALE_LOCK_CODE_HASH=$$(cd tests && CELLS_CONTRACTS_DIR=../$(TEST_DIR)/$(TARGET)/release $(CARGO) run --quiet --bin sale-code-hash) \
	  $(CARGO) build --release --target $(TARGET) --target-dir $(TEST_DIR)
	cd tests && CELLS_CONTRACTS_DIR=../$(TEST_DIR)/$(TARGET)/release CELLS_PRICE_DIR=../$(PRICE_DIR) $(CARGO) test

clean:
	$(CARGO) clean
	cd tests && $(CARGO) clean
