//! Everything that reads bytes a stranger wrote, fed bytes a stranger might write.
//!
//! The contract's attack surface is narrower than the codebase suggests. Almost all of it
//! is arithmetic on values the chain supplies, which cannot lie about their type. The
//! exception is the handful of functions that take a `&[u8]` off a cell and decide what it
//! means, and those bytes are whatever the person building the transaction put there:
//! `AccountData::parse` over a cell's data, `parse_price_factor` over the price cell, and
//! `validate_label` over a name.
//!
//! ## Why this is not cargo-fuzz
//!
//! cargo-fuzz needs nightly and a corpus directory, and a corpus that lives on somebody's
//! machine is a corpus that is not in CI. This sweeps a fixed number of inputs from a
//! seeded generator, so it runs everywhere `cargo test` runs, takes under a second, and a
//! failure reproduces from the seed printed in the message rather than from a file nobody
//! committed. It is weaker than real fuzzing at finding deep paths and stronger at being
//! run, which for a suite nobody is paid to babysit is the better trade.
//!
//! ## The three properties
//!
//! 1. **Nothing panics.** A panic in a CKB script aborts with the runtime's own exit code
//!    rather than a protocol error, so it fails closed, but it fails closed opaquely: the
//!    transaction is refused with a number that names nothing and the cause is invisible
//!    from outside. Every one of these must return an `Err`, never abort.
//! 2. **Round trip.** Anything `build_account_data` writes, `parse` reads back identically.
//!    A parser that agrees with its own writer on valid input, and refuses everything else,
//!    is the whole contract of this layer.
//! 3. **Truncation is refused, never interpreted.** The failure mode that matters is a
//!    short buffer read as a valid record with the fields shifted. Every prefix of a valid
//!    cell shorter than the header must be refused.

use cells_core::{build_account_data, parse_price_factor, validate_label, AccountData, DATA_HEADER_LEN, MAX_EXPIRED_AT};

/// xorshift64*, so a failing case is reproducible from the seed in the message and no
/// corpus file has to exist. Deterministic on purpose: a suite that finds a different
/// bug every run is a suite nobody can act on.
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    fn byte(&mut self) -> u8 {
        (self.next() >> 24) as u8
    }
    fn below(&mut self, n: usize) -> usize {
        if n == 0 {
            0
        } else {
            (self.next() % n as u64) as usize
        }
    }
}

/// A valid cell's data, to mutate from. Starting from noise alone almost never reaches
/// the interesting branches: the parser rejects the first byte and nothing further is
/// exercised. Most of these inputs are therefore a real record with something wrong.
fn valid(rng: &mut Rng, label: &[u8]) -> Vec<u8> {
    let mut wh = [0u8; 32];
    let mut next = [0u8; 20];
    let mut owner = [0u8; 20];
    let mut manager = [0u8; 20];
    for b in wh.iter_mut() {
        *b = rng.byte();
    }
    for b in next.iter_mut() {
        *b = rng.byte();
    }
    for b in owner.iter_mut() {
        *b = rng.byte();
    }
    for b in manager.iter_mut() {
        *b = rng.byte();
    }
    build_account_data(&wh, &next, rng.next() % (MAX_EXPIRED_AT + 1), &owner, &manager, label)
}

#[test]
fn parsing_a_cell_never_panics_and_never_misreads() {
    let mut rng = Rng(0x1234_5678_9ABC_DEF0);
    let mut parsed = 0;
    let mut refused = 0;

    for i in 0..40_000u32 {
        let data: Vec<u8> = match i % 4 {
            // Pure noise, of every length around the header boundary.
            0 => (0..rng.below(160)).map(|_| rng.byte()).collect(),
            // A real record with one byte corrupted: the case a length check catches and
            // a field check does not.
            1 => {
                let mut d = valid(&mut rng, b"alice");
                if !d.is_empty() {
                    let at = rng.below(d.len());
                    d[at] ^= 1 << rng.below(8);
                }
                d
            }
            // A real record, truncated. The failure that matters: a short buffer read as
            // a valid one with every field shifted.
            2 => {
                let d = valid(&mut rng, b"alice");
                let keep = rng.below(d.len() + 1);
                d[..keep].to_vec()
            }
            // A real record with rubbish appended, which is the label's territory.
            _ => {
                let mut d = valid(&mut rng, b"a");
                for _ in 0..rng.below(64) {
                    d.push(rng.byte());
                }
                d
            }
        };

        match AccountData::parse(&data) {
            Ok(a) => {
                parsed += 1;
                // If it parsed, every accessor has to be readable without going out of
                // bounds, and the header has to have actually been there.
                assert!(data.len() >= DATA_HEADER_LEN, "parsed {} bytes, shorter than the header", data.len());
                assert_eq!(a.witness_hash().len(), 32);
                assert_eq!(a.owner_lock_hash().len(), 20);
                assert_eq!(a.manager_lock_hash().len(), 20);
                assert_eq!(a.account().len(), data.len() - DATA_HEADER_LEN);
                assert!(a.expired_at() <= MAX_EXPIRED_AT);
                let _ = a.id();
                let _ = a.next();
                let _ = a.is_delegated();
            }
            Err(_) => refused += 1,
        }
    }

    // The control on the sweep itself. All-refused would pass every assertion above and
    // prove nothing; so would all-parsed.
    assert!(parsed > 1_000, "only {parsed} inputs parsed; the generator is not reaching valid records");
    assert!(refused > 1_000, "only {refused} inputs refused; the generator is not reaching bad ones");
}

#[test]
fn a_cell_this_writer_wrote_reads_back_exactly() {
    let mut rng = Rng(0xDEAD_BEEF_CAFE_F00D);
    for _ in 0..5_000 {
        let n = 1 + rng.below(40);
        let label: Vec<u8> = (0..n).map(|_| b"abcdefghijklmnopqrstuvwxyz0123456789"[rng.below(36)]).collect();
        let mut wh = [0u8; 32];
        let mut next = [0u8; 20];
        let mut owner = [0u8; 20];
        let mut manager = [0u8; 20];
        for b in wh.iter_mut() {
            *b = rng.byte();
        }
        for b in next.iter_mut() {
            *b = rng.byte();
        }
        for b in owner.iter_mut() {
            *b = rng.byte();
        }
        for b in manager.iter_mut() {
            *b = rng.byte();
        }
        let expired = rng.next() % (MAX_EXPIRED_AT + 1);

        let data = build_account_data(&wh, &next, expired, &owner, &manager, &label);
        let a = AccountData::parse(&data).expect("what the writer wrote, the reader must read");
        assert_eq!(a.witness_hash(), &wh[..]);
        assert_eq!(&a.next()[..], &next[..]);
        assert_eq!(a.expired_at(), expired, "five bytes of expiry, little endian, both ways");
        assert_eq!(a.owner_lock_hash(), &owner[..]);
        assert_eq!(a.manager_lock_hash(), &manager[..]);
        assert_eq!(a.account(), &label[..]);
    }
}

#[test]
fn every_prefix_shorter_than_the_header_is_refused() {
    // Exhaustive rather than sampled: there are only a hundred of them, and this is the
    // shape a buffer-length mistake takes.
    let data = build_account_data(&[7u8; 32], &[9u8; 20], 1_700_000_000, &[1u8; 20], &[2u8; 20], b"alice");
    for keep in 0..DATA_HEADER_LEN {
        assert!(
            AccountData::parse(&data[..keep]).is_err(),
            "{keep} bytes is shorter than the {DATA_HEADER_LEN} byte header and must be refused, not interpreted"
        );
    }
    assert!(AccountData::parse(&data[..DATA_HEADER_LEN]).is_ok(), "the header alone is the root's shape and is valid");
}

#[test]
fn the_price_cell_never_panics_and_only_accepts_its_own_shape() {
    // The price cell is a cell dep, so anybody can present any bytes as one. Reading it
    // wrongly moves the fee, which is the one number a stranger has a reason to move.
    let mut rng = Rng(0x0BAD_F00D_1234_5678);
    let mut some = 0;
    for i in 0..20_000 {
        // Half pure noise, half the right shape with a random factor. Noise alone never
        // reaches the accepting branch (it would have to guess the version byte and the
        // length), so a sweep made only of noise proves the refusal and nothing else.
        let data: Vec<u8> = if i % 2 == 0 {
            (0..rng.below(24)).map(|_| rng.byte()).collect()
        } else {
            let mut d = vec![cells_core::PRICE_DATA_VERSION];
            let factor = (rng.next() % 12_000) as u32;
            d.extend_from_slice(&factor.to_le_bytes());
            d
        };
        if let Some(f) = parse_price_factor(&data) {
            some += 1;
            assert!(f >= cells_core::PRICE_FACTOR_MIN && f <= cells_core::PRICE_FACTOR_MAX, "factor {f} outside its bounds");
            assert_eq!(data.len(), cells_core::PRICE_DATA_LEN, "a factor was read out of the wrong length");
            assert_eq!(data[0], cells_core::PRICE_DATA_VERSION, "a factor was read out of the wrong version");
        }
    }
    assert!(some > 0, "no random input was ever accepted; the generator never produced the right shape");
}

#[test]
fn a_label_is_judged_the_same_way_every_time() {
    // A label is the one attacker-controlled string that becomes a name. The property is
    // not which strings pass, it is that passing implies the alphabet, so a character
    // nobody thought about cannot arrive through a path nobody tested.
    let mut rng = Rng(0xFACE_B00C_0000_0001);
    let mut accepted = 0;
    for _ in 0..40_000 {
        let n = rng.below(46);
        let label: Vec<u8> = (0..n).map(|_| rng.byte()).collect();
        if validate_label(&label).is_ok() {
            accepted += 1;
            assert!(!label.is_empty() && label.len() <= 40, "accepted a label of {} bytes", label.len());
            for &c in &label {
                assert!(
                    c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-' || c == b'.',
                    "accepted a label containing byte {c:#04x}"
                );
            }
            assert!(label[0] != b'-' && label[label.len() - 1] != b'-', "accepted a hyphen at an edge");
            assert!(label.iter().filter(|&&c| c == b'.').count() <= 1, "accepted more than one level of nesting");
        }
    }
    // Random bytes almost never form a valid label, so this is checked against a shaped
    // generator rather than left as a count that would always be zero.
    for _ in 0..2_000 {
        let n = 1 + rng.below(40);
        let label: Vec<u8> = (0..n).map(|_| b"abcdefghijklmnopqrstuvwxyz0123456789"[rng.below(36)]).collect();
        assert!(validate_label(&label).is_ok(), "a plain alphanumeric label must be valid: {:?}", String::from_utf8_lossy(&label));
        accepted += 1;
    }
    assert!(accepted > 2_000, "the sweep never accepted anything");
}
