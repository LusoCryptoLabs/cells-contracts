# The protocol, as the contracts enforce it

What a `.cell` name is on chain and what each transaction has to satisfy. How it got here
is one paragraph at the end; the decision records under [decisions/](decisions/) carry the
reasoning.

## A name is a cell

One name, one live cell. Its lock is `account-lock`, which always succeeds and takes no
arguments, so every name shares one lock hash. Its type is `account-cell-type`, with twenty
bytes of arguments naming the namespace. Everything that matters is decided by the type
script, which CKB runs on the cell whenever it appears in a transaction, as an input or as
an output.

The suffix `.cell` is not stored. A label is 1 to 40 bytes of `a-z`, `0-9` and `-`, with no
hyphen at either end. One dot is allowed, for a sub-name such as `shop.alice`, and each
part obeys the same rule.

### The data

```
offset  bytes  field
0        1     version, always 0x03
1       32     blake2b of the witness that carries the records
33      20     next: the id of the successor in the ring
53       5     expires, unix seconds, little-endian
58      20     owner: the first twenty bytes of the owner's lock hash
78      20     manager: the same for the delegate; equals the owner when there is none
98      ...    the label
```

The id is not stored. It is `blake2b(label)[..20]`, recomputed wherever it is needed, and
the root sentinel, whose label is empty, has id zero by definition. A 40-character name
occupies 232 CKB, and every name locks a flat 240 CKB of refundable rent whatever its
length.

Records live in the witness, not in the cell, and the cell holds their hash. A record is a
`key`, a `label` and a `value`. Keys are `address.<coin type>` (SLIP-44; `address.309` is
CKB), `profile.<field>`, `dweb.ckbfs`, `fiber.node`, `fiber.addr` and `custom.<anything>`.
The set is capped at 52 KB.

### Why twenty bytes

Owner, manager, next and the namespace are twenty-byte prefixes of thirty-two-byte hashes.
The rule that decided which fields could be cut: truncate a value an attacker has to match
against something already fixed, which is a targeted second preimage at 2^160; never one
where the same party chooses both sides, which is a birthday problem at 2^80. The witness
hash keeps its thirty-two bytes for exactly that reason. Every comparison against a stored
twenty bytes compares twenty against twenty, and a mismatch in length fails closed, since
slices of different lengths are never equal.

## The ring

There is no list of taken names for a type script to consult, so uniqueness is a shape.
Every live name points at the next id up, the largest wraps to the root, and the root at
id zero closes the circle. Each name covers the open range between its own id and its
`next`.

To register `x`, spend the one name whose range contains `x` and recreate it pointing at
`x`, with `x` pointing where it used to. Two people registering the same label must both
spend the same predecessor, and the chain lets only one of them. To recycle an expired
name, spend it and its predecessor, and recreate the predecessor pointing past it. Both
moves preserve the partition, and a property test over thousands of random operations
says so on every run.

The predecessor is a stranger's cell, spent without their signature. So the type script
holds it byte for byte except `next`: its records hash, expiry, owner, manager, label, lock
and capacity may not change. Capacity may not shrink on any action at all.

## The actions

The action name travels as ASCII in `witnesses[0].input_type`. Each validator pins how
many name cells go in and how many come out, so actions cannot be batched or confused.

| action | in, out | who | what is checked |
|---|---|---|---|
| `register` | 1, 2 | anyone | the new id strictly inside the predecessor's range; the relink exact; a matured commit (below); a term of 1 to 10 years; the rent; the fee to the treasury; the manager equal to the owner; the new cell wearing `account-lock`; for a sub-name, the parent as a cell dep and an input under the parent's owner |
| `renew` | 1, 1 | anyone for a plain name, the parent's owner for a sub-name | only the expiry grows, by 1 to 10 years; the fee to the treasury; a sub-name never past its parent |
| `edit_records` | 1, 1 | owner or manager | only the witness changes |
| `edit_manager` | 1, 1 | owner | only the manager changes, and never to zero |
| `transfer` | 1, 1 | owner | only the owner changes, never to zero and never to the account-lock; the manager is reset to the new owner |
| `recycle` | 2, 1 | anyone | the target is the predecessor's immediate successor; the target input's `since` is an absolute timestamp past its expiry plus thirty days of grace; the root is never recyclable |
| `genesis` | 0, 1 | once | the root alone, with no owner, consuming the one-time genesis token whose type hash is this script's argument |

"Who" is proven by spending: an owner action must spend, in the same transaction, a cell
whose lock hash begins with the twenty bytes recorded as owner. The type script checks no
signature. Which algorithm that lock runs is the lock's business, which is why a name can be
owned by CKB's SPHINCS+ lock today ([0016](decisions/0016-post-quantum-owner.md)).

### Commit, then reveal

A registration must spend a commit cell the registrant made earlier: an ordinary cell
under the registrant's own lock whose data is `blake2b(namespace ‖ label ‖ owner ‖
secret)`, with its input `since` set to a relative timestamp of at least sixty seconds.
The commitment hides the label, binds the owner and binds the namespace, and the chain
itself refuses to mine the reveal early. A commit held by anyone but the committed owner is
refused ([0004](decisions/0004-commit-reveal.md)).

## Money

The fee is per year, by the length of the label, paid as an output to the treasury lock,
whose hash is compiled into the contract:

| characters | CKB a year |
|---|---|
| 5 or more | 5,000 |
| 4 | 20,000 |
| 3 | 80,000 |
| 2 | 200,000 |
| 1 | 500,000 |

A sub-name is charged a fifth of its parent's line, whatever its own length. One year in
five is free, so ten years are billed as eight ([0023](decisions/0023-a-fifth-for-a-child-and-a-free-year.md)).
A registration may name an inviter, an existing name presented as a cell dep, and a tenth
of the fee then goes to that name's owner instead of the treasury; the buyer pays the same
either way. The treasury itself, and anyone who signed the transaction, are refused as
inviter ([0011](decisions/0011-referrals.md)).

Only pure outputs count as payment: an output carrying a type script is not a payment,
whatever its capacity. And the account contract reads the sale locks being spent beside it
and adds what they owe to its own requirement, so one treasury output cannot answer two
contracts.

### The price cell

One cell, under its own type script, holds a factor in basis points from 126 to 10,000
that multiplies every line of the schedule at once. It can only discount: the schedule is
the ceiling, and if the cell is missing or malformed the full schedule applies. Its own
script lets it move by at most a sixteenth every six hours, under the same lock and with
the same capacity. A key that can move it can lower revenue slowly and visibly; it cannot
raise a price above the schedule, and it cannot touch a name
([0014](decisions/0014-repricing-without-an-oracle.md)).

### Selling

A seller transfers the name's ownership to `sale-lock`, whose arguments are the seller's
lock hash and the price in shannons, and leaves one small cell under it as the listing. A
buyer spends that cell and takes the name in the same transaction. The lock accepts only if
the seller receives the price and the protocol its share, both as pure outputs, and the
listing's own deposit returns to the seller. The seller cancels by spending the listing
themselves. The protocol's share is one percent at 6,300 CKB and above, a flat 63 CKB
between 630 and 6,300, and nothing below, because the share has to be a cell and a cell
cannot hold less than its own bytes ([0012](decisions/0012-selling-a-name.md),
[0025](decisions/0025-one-percent-on-a-sale.md)).

## Errors

The exit codes the scripts return, from `cells-core`:

| code | name | when |
|---|---|---|
| 20 | `MalformedAccountData` | the cell does not parse as a name |
| 21 | `WitnessHashMismatch` | the records do not hash to the cell |
| 24 | `NotInPredecessorRange` | a registration outside the spent name's range |
| 25, 26 | `LinkedListBroken`, `DuplicateId` | the relink is wrong |
| 27 | `StructuralDrift` | a field changed that the action does not allow |
| 28 | `NotExpired` | recycling a name that is not past grace |
| 29 | `Unauthorized` | no input under the owner, the manager, or the parent's owner |
| 30, 31 | `InvalidCharset`, `InvalidLength` | the label |
| 35 | `InsufficientPrice` | less than the rent locked |
| 36, 37, 47 | `CommitMissing`, `CommitTooYoung`, `CommitNotOwned` | the commit |
| 38 | `NullOwner` | an all-zero owner |
| 39, 43 | `ExpiryTooSoon`, `TermTooLong` | the term |
| 40, 41, 45 | `ParentMissing`, `ParentOutlived`, `TooDeep` | sub-names |
| 42 | `TreasuryUnpaid` | the fee |
| 44 | `OwnerIsCellLock` | owner or manager set to the always-success lock |
| 46 | `RootNotRecyclable` | the sentinel |
| 48 | `CellLockNotAccountLock` | a new name wearing another lock |

Codes 22, 32, 33 and 34 are still in the enum and can no longer be reached: the stored id,
the sequencer and the config cell they named were all removed.

## Off chain by design

A wallet's primary name is a small cell under the wallet's own lock with no type script,
trusted only if the name it claims is owned or managed by that wallet, so a forged one
resolves to nothing. A payment request is a message the owner signs, carried in a link and
checked by the payer against the chain; the destination is always read from the name's
own records, never from the link. Neither needs a contract, and neither is in this
repository.

## How it got here

Version one locked each name with omnilock and let a sequencer drive registration
([0001](decisions/0001-lock-and-auth-model.md)). Version two made registration
permissionless under the always-success lock, with the owner as a hash in the data
([0002](decisions/0002-permissionless-registration.md)), then added the manager
([0006](decisions/0006-manager-and-reverse.md)), commit-reveal
([0004](decisions/0004-commit-reveal.md)) and the fee
([0009](decisions/0009-economics-and-the-upgrade-key.md)); a forgeable config cell was
removed and genesis tied to a one-time token. Version three, the layout above, cut every
matchable hash to twenty bytes, dropped the stored id, and put a version byte first so
that the next change is an upgrade rather than a redeploy
([0015](decisions/0015-cell-size.md)). Mainnet opened on that layout.
