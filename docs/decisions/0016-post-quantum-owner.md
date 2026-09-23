# 0016: A post-quantum owner, without touching the contract

Status: **Decided 2026-09-10, proven on Pudge.** A name can be owned by a key no quantum
computer is expected to break, today, with the contract, the SDK and the app unchanged.
Nothing is forced on anyone: a JoyID user keeps using JoyID.

## The question

Is Cells quantum resistant? No name secured by an elliptic-curve key is: JoyID signs with
passkeys and the CKB default lock with secp256k1, both of which Shor's algorithm breaks on
a large enough machine, and every owner's public key is already on chain in the witness of
their registration. NIST deprecates ECDSA after 2030 and disallows it after 2035. The
honest question is not whether we are safe, nobody is, but whether we can move, and what
it costs.

## Why the contract does not care

`account-cell-type` verifies no signature. Ownership is a lock hash in the cell's data, and
an owner action is proven by spending, in the same transaction, a cell under that lock
(`signed_by`, decision [0001](0001-lock-and-auth-model.md)). Which algorithm the lock runs
is the lock's business. The test suite makes the point by accident: the owners in it are
synthetic always-success locks with args like `owner-a`, not any wallet's lock, and the
suite passes.

CKB has an official post-quantum lock: `sphincs-all-in-one-lock` from
[nervosnetwork/quantum-resistant-lock-script](https://github.com/nervosnetwork/quantum-resistant-lock-script),
SPHINCS+ as standardised in FIPS 205 (SLH-DSA), all twelve parameter sets, M-of-N multisig
built in, audited by ScaleBit in December 2025, deployed on mainnet (a type-id cell under a
3-of-5 multisig of named Cryptape people) and on testnet (by data hash). Its format is
documented: args are a blake2b of a five-byte prefix and the public key, the witness carries
prefix, public key and signature, and the signed message is `CKB_TX_MESSAGE_ALL` under the
lock's own personalization.

So a name transferred to an address under that lock has a post-quantum owner. The owner
field is twenty bytes of a lock hash; the contract accepts it like any other.

## The recipe: quantum owner, everyday manager

| Action | Who signs |
|---|---|
| Edit records, be paid, ask to be paid | owner **or manager** |
| Renew | anyone |
| Transfer, change the manager, issue a sub-name | owner only |

Owner under SPHINCS+, kept cold. Manager an everyday wallet, JoyID or whatever the person
already uses, for records and daily use. Theft needs the owner key.

One rule of the contract shapes the order: **a transfer resets the manager to the new
owner**, so a seller's delegate never survives a sale (`transfer_rejects_manager_not_reset`).
The delegation therefore happens *after* the transfer and is signed by the quantum key,
once. That single signature is why a signer was needed: without one, a name parked under
the quantum lock is safe but frozen.

## What was built

A CCC signer for the SPHINCS+ lock, single-signature form, lives in the SDK
(`cellula-sdk`) and stands in for a wallet wherever the SDK asks for a signer. The
application's screens for protecting a name, and the recovery path for a lost everyday
wallet, are documented with the application, which is not in this repository.

## Proof, on Pudge, 2026-09-10

The throwaway `v3-first-name.cell`, owned by the ordinary user key:

1. 300 CKB to the quantum address:
   `0x5bc3bc69f0939aff4f205424a1129766a2fcd0c100440e336807489c0e834bc4`.
2. A plain spend from the quantum address, signed by the signer, accepted by the real lock:
   `0x9129954b29a08258ca0d77f9b98458b8fa0b09dfa46cbd830853a265f191db6e`.
3. Transfer of the name to the quantum owner, signed by the user key; the contract reset the
   manager to the new owner:
   `0x08b662bbe41258171b98864c2966cfeaa619cfd89c79d3fe3f362bcc18d4c829`.
4. The quantum owner delegates to the user key, signed by SPHINCS+ through the unchanged SDK:
   `0x2d0329838bc730479151d75f02b1c6f86072616532a71d97d915607f7f96aacd`.
5. The manager, an ordinary key, edits a record:
   `0x1795259e43d4bc44908962b825a6c0865e56e320c925ee98354fc544d7bdcb56`.
6. Controls: the manager may neither transfer nor re-delegate. Refused by the SDK before
   the chain; on the chain by `set_manager_rejects_by_manager` and the owner check in
   `validate_transfer`, both in the contract suite.
7. Cleanup by the manager:
   `0x9780e6d1c4b8d054d4085cc5925104b7b7efd08fab1b782cef966be83dd40b92`.
   The quantum owner hands the name back, signed by SPHINCS+:
   `0x8d053fb0e71d6679405d7dd079cfa7c09b1bf21664f282848e287657485b4c98`.

The resolver showed the twenty-byte quantum identity as the owner throughout
(`0xd5026c2c742a379b0c422271a4e1f59b211a6c31`).

## The other owner actions

**Renewing** needs nobody: it is permissionless, so a protected name is renewed by
anyone, including the wallet that manages it.

**Clearing an expired name** needs nobody either: `validate_recycle` contains no owner
check at all, only proof through consensus timing that the name is past its expiry, so a
quantum owner changes nothing about it (decision [0005](0005-recycle-deposit.md)).

**Issuing a sub-name** does need the parent's owner, and it is the one action where two
keys must sign the same transaction. `register` takes `parentSigner`: the parent's owner
spends one ordinary cell of their own, which is handed straight back in an output of the
same capacity, purely so the contract can see their authority, while the wallet pays for
the sub-name and receives it. Their witness placeholder is put in before the fee is
sized, because a quantum signature is eight kilobytes and a fee sized without it is
refused by the node. The two signatures cover different script groups, so neither
disturbs the other.

Two constraints surfaced doing it, both older than this decision and neither obvious:

- **A parent needs more than a year left to issue a sub-name.** A sub-name may not
  outlive its parent, and the shortest term is a year, so a parent inside its last year
  must be renewed first. The SDK says so before anything is signed.
- **The parent's owner must hold an ordinary cell.** A key that owns a name but holds no
  spendable cell has nothing to prove authority with; the protect flow leaves 100 CKB
  there for exactly this kind of reason.

## What it does not solve, and what each would take

- **The manager controls where money goes.** A quantum owner protects the name, not the
  payout records, while an elliptic-curve manager is set. On the day that matters the owner
  removes the manager with the quantum key, or delegates to a quantum key.
- ~~**Signed payment requests** cannot be signed by a quantum owner.~~ **Done.**
  `PqSigner.signMessage` signs one, and the SDK verifies it under its own sign type
  (`CellsSphincsPlus`), with the public key as the identity, from which the lock is
  rebuilt without a wallet. The digest is domain-separated from the one the lock
  verifies, so a request signature can never be replayed as a transaction signature,
  and a test asserts the two digests differ. A signature is 7,856 bytes, and hex doubles
  it, so such a request link measures about sixteen kilobytes against six hundred bytes
  for an ordinary one: fine to send, far too big for a QR code.
  **The manager may now sign requests too**, on both sides, asking and verifying, which
  is what a protected name actually needs day to day, and it grants nothing new: a
  manager already edits the records, which is where the money goes. The pay page names
  who signed. Proven against the chain on the protected name: the manager's request
  verifies as `manager`, the quantum owner's as `owner`, and a stranger is refused before
  anything is signed.
- **No hardware.** No consumer device signs SLH-DSA. The key is a file, like the other
  testnet keys, and belongs on an offline machine when it guards something real.
  QuantumPurse holds the same kind of key but signs only its own transactions.
- **The 20-byte identities** ([0015](0015-cell-size.md)) go from 2^160 to 2^80 for a
  targeted collision under Grover. Out of reach for any foreseeable machine, but the one
  place quantum changes our own numbers; a later layout could restore 32 bytes.
- **The upgrade key** is a single elliptic-curve key and the one systemic risk: a forged
  upgrade replaces the contract for everyone. It moves to the SPHINCS+ lock, as a multisig
  when there are people to hold keys, before 2030 or the first credible sign of a
  cryptographically relevant quantum computer, whichever comes first. Reference the lock by
  **data hash** and keep the binary, so that what a name obeys is fixed by its content. Rehearse on testnet with a
  real upgrade signed by SPHINCS+ before doing it where it counts.
- **The treasury lock** is compiled in and is an elliptic-curve key; changing it is an
  upgrade, so the mainnet treasury should be chosen with this in mind.
- **The Lightning route** inherits Bitcoin's exposure.

## The lock we point people at

Our contract enforces no algorithm: an owner action needs the transaction to spend a cell
whose lock hash starts with the twenty bytes recorded as owner, and CKB-VM runs whatever lock
that cell carries. So the quantum guarantee is exactly as good as the lock script we point
people at, which is somebody else's code. Two things were done about that.

### The build reproduces (2026-09-11)

Before freezing anything, the bytes had to be accounted for, the same discipline
[TRUST.md](../TRUST.md) applies to our own contracts. The project publishes a
`checksums.txt` and a recipe, `scripts/reproducible_build_docker`, which runs `make`
inside `cryptape/llvm-n-rust` pinned by image digest, not by tag. Run at commit
`082c0a1`:

```
docker run --platform=linux/amd64 --rm -v <repo>:/code   docker.io/cryptape/llvm-n-rust@sha256:d6d1f9a6656039273210de91913c828f5b4aa4a3282d2c93ed19bcb7bbf728fe   make clean build
sha256sum -c checksums.txt        # all ten artefacts OK
```

The lock it produces is **byte for byte the code deployed on mainnet**: 211,296 bytes,
CKB hash `0x49417a0e…`, identical to the cell fetched from the chain, whose SHA-256 is
also the first line of their `checksums.txt`. So the chain, the published artefact and
the source all agree, and freezing these bytes freezes something we can account for.

Two things learned on the way, both worth keeping. An ordinary `make build` with the
system toolchain (clang 18.1.3, rustc 1.96) produces a **different** binary; only the
pinned image reproduces, so "we built it and it looked right" would have been worthless.
And the **testnet cell is a different, older build** (216,544 bytes, `0x147ecbb5…`),
which no published checksum covers: every quantum proof run on Pudge so far ran against
code we have not accounted for, and the rehearsal below should use the mainnet bytes.

### Decided: the audited upstream lock, watched (2026-09-11)

Two options were weighed. **Burn our own copy**, pinned by data hash so nothing can
replace it, at the cost of about 211,422 CKB locked away forever and of freezing any
future fix along with the code. **Or keep the upstream type id and watch it**, which is
cheaper and gets fixes for free, but detects rather than prevents.

We went with the upstream lock, for reasons that are worth writing down because they are
reversible if any of them changes:

- **It is audited.** ScaleBit, December 2025, linked from the project's README. The main
  argument for freezing was that young cryptographic C code should not be trusted blind,
  and an audit plus a year of quiet weakens it.
- **It is reproducible, and we reproduced it.** The deployed mainnet bytes are the
  published artefact, built from source in their pinned image. Freezing adds nothing to
  what we know today; it only fixes what we may learn tomorrow.
- **A fix reaching everyone at once has real value** in code this new, and the people who
  would ship it are named and accountable. A frozen copy would leave every name behind it
  on the old code until each owner migrated, and an owner who keeps their key offline is
  exactly the person who would not hear in time.
- **The failure we cannot recover from is the silent one**, which is what the watch is
  for.

What that obliges us to do, and what is now built:

1. **Watch the code, not the cell.** The resolver compares the
   deployed code's own hash against `SPHINCS_LOCK[network].dataHash`, every ten minutes,
   on both networks, from whichever network the resolver runs on. It follows the type id
   when an upgrade moves the cell, so "moved" and "changed" are different answers, and an
   unreachable node reports `unchecked` rather than crying wolf. `GET /quantum` and
   `/health` carry the verdict.
2. **Stop, not warn.** When the code is not what we recorded, the protect screen says so,
   shows both hashes, and **disables the button**. Putting a name behind code we cannot
   vouch for is the one thing that screen exists to prevent. The way out is on our side:
   look at the change, and redeploy with the new hash recorded.
3. **Keep the door open.** Ownership is only a lock hash, so nothing stops us pinning a
   frozen copy later, or supporting a second lock beside this one. Burning our own copy
   stays costed and ready in this document if the reasons above stop holding.
