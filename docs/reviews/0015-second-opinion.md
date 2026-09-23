# Second opinion on decision 0015: five AccountCell layout changes

Independent review, 2026-09-09. The reviewer was given the code and the five proposed
changes and was forbidden from reading `docs/decisions/0015-cell-size.md`,
`docs/AUDIT-PLAN.md` and the pass-5 section of `docs/SECURITY.md`, so that its reasoning
would be its own. Reproduced verbatim; the decision's response to it is in the ADR.

Paths outside `contracts/` refer to the application, which is not in this repository, and
every line number is as of 2026-09-09.

Paths abbreviated: core = `contracts/crates/cells-core/src/lib.rs`, type =
`contracts/contracts/account-cell-type/src/main.rs`, sale = `contracts/contracts/sale-lock/src/main.rs`,
price = `contracts/contracts/price-cell-type/src/main.rs`, codec = `sdk/src/codec.ts`,
client = `sdk/src/client.ts`, request = `sdk/src/request.ts`, gw = `services/gateway/src/`,
registrar = `services/registrar/src/lib.rs`, indexer = `services/indexer/src/lib.rs`,
tests = `contracts/tests/tests/account_cell.rs`, testtool = ckb-testtool 0.14.1 sources,
ckbver = ckb-verification 0.119.0 `transaction_verifier.rs`.

Baseline (VERIFIED): layout core:19-27, 36-40; root core:43,47. Occupied size today: v1 = 8 + 33 (lock, no args) + 65 (type, 32-byte args) + 112 + n = 218+n CKB, v2 = 251+n (core:922-923 computes exactly this). With all five changes: header v1 65 (wh 20, next 20, exp 5, owner 20), v2 86, type 53; occupied v1 159+n, v2 180+n; worst case (v2, 40 chars) 220 CKB; saving 59 CKB per v1 name, 71 per v2.

---

## Change 1: remove `id`, derive from the label

**(a) Sites.** On-chain reads: core:585-589 (`id()`), type:74 (root detection), 77 (integrity `id == account_id(label)`), 207 (genesis), 238 (register root guard), 261 (`between`), 265 (relink), 722-728 (recycle picks the predecessor by id), 750 (immediate successor), 753 (`covers`), 765 (root recycle guard), 782 (`core_fields_unchanged`). Writers: core:291, 330; codec:451, 486; tests:149, 170; `scripts/fixtures.json` root/root_after/alice blobs. Off-chain readers: codec:527, 560; client:512, 641, 721, 730, 758, 916-917, 1012, 1042-1043, 1089-1090, 1123, 1132-1133, 1256-1257, 1275-1276, 1307-1308; registrar:63-65, 68, 75, 98, 108, 113 and bin/register.rs:47, 58, 79, 82; gw/registry.ts:72-78 (reads id from raw hex offset 64..104 of historical outputs), 129-130, 166-168; gw/avatar.ts:164, 169, 207; gw/server.ts:353, 474, 477 (the archive fallback already derives `accountId(lbl)`); ui Profile.tsx:113-114, MyNames.tsx:99,110, Explore.tsx:180, Market.tsx:284,303, Face.tsx:26,40, FiberPanel.tsx:185, DirectoryPanel.tsx:69, Primary.tsx:123, remind.ts:112; scripts 05-resolve.mjs:23, 06-register.mjs:69,77,90, 13-root-guard-proof.mjs:42,48, 37-id-redundancy.mjs:24; tests:1049-1056, 1485-1502; `sdk/test/codec.test.ts`:45-48, 65, 169, 180. Not readers: indexer:35-47 (label/expiry/owner only); sale:74-122 and price:97-159 never parse AccountCell data.

**(b) What it protects.** Nothing independent of the label. type:77 rejects any output whose stored id is not `blake2b(label)[..20]`, and inputs are trusted by induction (type:64-65), so on every live cell the field is a pure function of the label. Attack model unchanged: 160-bit id space; blocking a chosen name is a targeted second preimage, 2^160; a birthday pair (2^80) yields two attacker-chosen labels, griefing only (SECURITY.md T-3).

**(c) Semantic breakage.** The root: `ckb_blake2b256(b"")[..20]` is `0x44f4c69744d5f8c55d642062949dcae49bc4e7ef` (VERIFIED by computing `ccc.hashCkb` of the empty input), not `ROOT_ID`. The derivation must be `empty label -> ROOT_ID, else account_id(label)`; without that, genesis (type:207) fails and the root's "lo == hi == 0 covers everything" (core:622-623, 637-642) breaks. With it: type:74 collapses to `account().is_empty()`; type:238 and 765 keep working on derived ids; `predecessor_preserved` (type:792-818) never used id; recycle's predecessor selection (type:722-728) becomes label equality, equivalent because the ring keeps labels unique; a non-root output with an empty label is refused at type:238. `AccountIdMismatch` (core:377) and tests:1049-1056 become dead; tests:1485-1502 still fails, but via `NotInPredecessorRange` (label "old" derives p's own id and `between` excludes endpoints, core:640). `parseAccountLite` (codec:554-566) must hash every cell it scans (client:384-395, 639-642, 1122-1127). gw/registry.ts:72-78 must derive from the label. Cycle cost of one blake2b of at most 40 bytes per `id()` call: INFERRED negligible against the 100M budget (tests:29), not measured.

**(d) SAFE WITH CONDITIONS**: the empty-label mapping; keep type:238 and 765; every raw-offset reader above; fresh namespace (see misses, 2). Strongest reason: type:77 already makes the field carry zero information beyond the label, so removing it removes no check and grants no capability.

## Change 2: type args 32 -> 20

**(a) Sites.** type:926-935 (`namespace_id`, refuses args < 32, copies 32), 940-949 (`require_genesis_token`, `&h == token_type_hash`, h is `[u8; 32]`), 202, 476-479; core:201-213 (`commitment` takes `&[u8; 32]`). Off-chain: codec:267-271 (throws unless 32); client:299-305 (`accountType()` args = `dep.configTypeHash`), 665; request:89-90, 131, 256, 297 (`isHex(r.ns, 32)`), 310, 466; gw/deployment.ts:20, ui/deployment.ts:20; scripts 02-deploy.mjs:51-63 (namespace = the genesis token's full type hash), 03-genesis.mjs:15, 06-register.mjs; tests:277-280, 355-356; `contracts/tests/tests/registrar_loop.rs`:48-50, 78-80; `.testnet/deployment.json` `configTypeHash`/`genesisToken.typeHash`; core:922-923 and codec:153 hard-code `(32 + 1 + 32)`.

**(b) What it protects.** (i) The genesis singleton: a second genesis in the same namespace (second root, second ring, duplicate names, the H-1 class) must spend an input whose type-script hash equals the args (type:944). The attacker chooses that input's type script freely; the target is fixed at deploy (02-deploy.mjs:55): targeted second preimage on 160 bits of `blake2b(script)`, 2^160. Not a birthday: the attacker does not choose the namespace id. A look-alike namespace deployed with the same 20 args also needs such a token at its own genesis (type:202), same bound. (ii) Commitment domain separation (core:196-198): still one namespace per prefix except at 2^-160.

**(c) Breakage.** type:929 must accept 20; type:944 prefix compare; `commitment` parameter to 20 in Rust and TS (core:202, codec:271); request format (request:297, SPEC §10) either carries 20 bytes or keeps the full token hash while request:466 compares consistently. The type hash changes, so this is a new namespace. The tripwires core:922-923 and codec:153 must say 20 (else they over-estimate the minimum, the safe direction, but the "measured" figure at core:87-89 goes stale).

**(d) SAFE WITH CONDITIONS** (the sites above, fresh deploy). Saving 12 CKB. Strongest reason: it is compared exactly once, at genesis, against a freely chosen script's hash, a 2^160 targeted problem.

## Change 3: `owner_lock_hash` and `manager_lock_hash` 32 -> 20

**(a) Sites.** core:27, 43, 204/210, 286/294, 324-325/333-335, 592-594, 598-604. type:244 (`reject_null_owner`, length-agnostic), 248-250, 608, 649 (`reject_cell_lock_authority`: `hash == &cell_lock[..]`, type:845-850), 256, 287, 368-371 (`owner != &TREASURY_LOCK_HASH[..]`, `signed_by` 387-389, `paid_to` 392-408), 477-479 (owner copied into the commitment), 499 (`holder[..] != *x.owner_lock_hash()`), 566, 577 and 891-898, 593, 610/656 and 880-887, 648, 653, 666, 736-737, 799-800, 824-829. sale-lock compares its own 32-byte args against 32-byte input/output lock hashes (sale:15, 54, 79, 130, 154, 177) and never reads AccountCell data: unaffected, and must not be truncated. price-cell-type: no owner use. Off-chain: codec:12, 28, 272, 454/488 (length check throws on 32 bytes), 521-522, 563; client:506, 512, 566, 622-628, 663, 714, 768, 800, 913, 1009, 1039, 1042-1043, 1200 (offers map keyed by the full sale-lock hash) against lookups by `ownerLockHash` at 1217, 1270, 1301, and 1246, 1256-1257, 1275-1276, 1307-1308; request:202-203, 473-479, 486, 542; indexer:20, 40-41, 164-168; registrar:86, 104-105, bin/register.rs:38-43; gw/server.ts:160; ui Bell.tsx:155, Explore.tsx:75,178, Delegate.tsx:23,41-44, FiberPanel.tsx:62-63,117, MyNames.tsx:39,97, Market.tsx:89,98-99, NamePage.tsx:68,72-73,176, RegisterPanel.tsx:204,285,343, Profile.tsx:81; scripts 06, 10, 11, 12, 14, 16, 17, 19, 20, 21, 22, findtreasury.mjs; tests:303-324 (writes 32 bytes at OFF_OWNER/OFF_MANAGER), 355-364; registrar_loop.rs:58-59, 137-144.

**(b) What it protects.** Every owner action (edit, delegate, transfer, sub-name creation at type:287, referral payee at type:368) and the commit binding (type:499). Authentication is "some input's lock hash equals the stored value" (type:880-887). The attacker needs a spendable input whose script hash[..20] equals the victim's fixed value; code_hash, hash_type and args are freely choosable (an always-success code is even deployed: account-lock): targeted second preimage, 2^160 per name, 2^160/N across N names. Birthday is only available where one party controls both sides (a registrant choosing its own owner; a seller grinding two sale-lock scripts with a shared prefix, 2^80) and buys nothing: the registrant already picks any owner, the seller can already cancel and relist (sale:82-88). Same 160-bit class as CKB's blake160 lock args (the JoyID treasury args at codec:248) and as the id (T-3).

**(c) Semantic breakage.** Two guards fail OPEN if the compares are not rewritten to prefixes: type:845-850 (a 20-byte owner or manager never equals a 32-byte `cell_lock`, so owner = account-lock hash[..20] is accepted, and with `require_owner` prefix-matching any AccountCell input then authorizes: the L-1 "public property" hole reopens) and type:368-371 (treasury named as inviter, fee output counted as fee and cut, the case type:336-340 describes). Everything else fails CLOSED (`Unauthorized`, `CommitNotOwned`; every TS `===` against `script.hash()` silently false: `ownedNames` empty, `primaryName` null). `ROOT_OWNER` becomes 20 zeros. The commitment pre-image shrinks (core:207-211, codec:275-280): `commit()` at client:663 must truncate or no reveal ever matches. The offers map key (client:1200) must be the truncated hash. tests:1638-1640 encodes the v2 boundary as 1 + OWNER_HASH_LEN = 33 chars; it becomes 21 and the assert at :1640 catches it.

**(d) SAFE WITH CONDITIONS**: all compare sites in one change, above all 845-850 and 368-371; otherwise UNSAFE (anyone edits, transfers and sub-names a name whose owner is the account-lock prefix). Saving 12 CKB (v1), 24 (v2). Strongest reason: the cryptographic assumption (2^160 targeted second preimage on a script hash) is the one CKB's default locks already make, but the truncation turns two fail-closed guards into fail-open ones.

## Change 4: `expired_at` 8 -> 5 bytes

**(a) Sites.** core:22-23, 293/332, 584-588; type:290, 310-316, 563, 590, 623, 676-678, 690-693, 704, 735, 768 with 902-913 (`since` value is 56-bit, :909); codec:16-17, 453/487, 529/562; scripts 05-resolve.mjs:25, 09-price-proof.mjs:63 (raw offset 72); tests:151, 172; `docs/SPEC.md`:57.

**(b) What it protects.** Nothing cryptographic. Range 2^40 s, roughly year 36,800. The contract bounds it: register term at most 10 years from the commit header (type:309-316), renew extension at most 10 years (type:690-693), arithmetic saturating, and a 40-bit value always fits the 56-bit `since`.

**(c) Breakage.** Offsets after 72 shift by 3; encoders write 5 bytes and should refuse values at or above 2^40 (client:748 accepts a user-supplied expiry). The v1/v2 marker moves with `OFF_VERSION`.

**(d) SAFE.** 3 CKB. A u32 would be a year-2106 bug; 5 is the right cut.

## Change 5: `witness_hash` 32 -> 20

**(a) Sites.** core:19-20, 282/290, 310, 320, 351, 568-570; type:81-84 (`ckb_blake2b256(&payload)[..] != *a.witness_hash()`: 32 vs 20 rejects every output unless `[..20]`), 596, 643, 679, 739, 803 (stored vs stored); codec:13, 450/484, 469/507, 517-518; client reuses stored values (720/729, 1012, 1042, 1089, 1132, 1256, 1275, 1307); indexer:36 (same slice trap); gw/archive.ts:62, 66-76 (`hashCkb(witness) !== witnessHash` silently stops archiving), 97-104 (drops every stored file), 120-127; gw/server.ts:477, 498-501; gw/avatar.ts:144; scripts 05-resolve.mjs:41-44, 20-cache-proof.mjs:139; registrar:102-103, bin/register.rs:53-54; tests:146-148, 167-169; codec.test.ts:45-47.

**(b) What it protects.** The binding of a live cell to its records: every output must carry a witness hashing to the field (type:81-84); resolvers read the witness from the creating tx and verify (client:419-422, codec:517-518); the archive verifies out-of-band copies (archive.ts:72, 103). A stranger substituting records on someone else's name: second preimage, 2^160. The record author grinding a colliding pair: order 2^80 (INFERRED), but the author already has unrestricted `edit_records` (type:558-578), and a transfer's witness is supplied by whoever builds it (the buyer), so a seller cannot inject the twin. No party gains a capability.

**(c) Breakage.** Prefix compare at type:82, indexer:36, codec:518, archive.ts:72 and 103, 05-resolve.mjs:43; builders truncate (core:310, 351; codec:469, 507); archive files are named by 32-byte hashes and need re-indexing; every offset shifts by 12; the drift vector re-anchored.

**(d) SAFE WITH CONDITIONS** (the compares above). 12 CKB. Strongest reason: only the party that already controls the records can exploit a collision; strangers face 2^160.

---

## Cross-cutting checks

- **v1/v2 rule.** Premises: a valid label's first byte is `[a-z0-9]` (core:250-266: the first part's byte 0 cannot be `-` at i == 0 nor `.`), the root is exactly one header long (type:213), and a v2 cell must be at least the v2 header (core:553-559). None of the five changes touches these; only `OFF_VERSION` moves (112 to 65 with all five). tests:1622-1643 are written against the constants except the 33-char fixture (:1638-1640), see change 3.
- **Removing `id`** against the root, `covers`/`between`, `predecessor_preserved`, `validate_recycle`, `parseAccountLite`: change 1 (c).
- **Owner truncation** against `require_commit` (:499), `reject_cell_lock_authority` (:845-850), the treasury comparison (:368-371), `signed_by` (:387-389): change 3 (c).
- **What a green suite proves.** VERIFIED: ckb-testtool 0.14.1 `verify_tx` (testtool context.rs:463-500) runs `verify_tx_consensus` (context.rs:443-446), which is only `OutputsDataVerifier` (testtool tx_verifier.rs:13-24: outputs count equals outputs_data count), then `TransactionScriptsVerifier::verify` (scripts only). CKB's occupied-capacity rule is `CapacityVerifier::verify` (ckbver:481-518, `InsufficientCellCapacity` at :506-513) inside `ContextualTransactionVerifier` (ckbver:107-118), which ckb-testtool never constructs. Consistent with the harness: every cell is created at CAP = 100 CKB (tests:30, 331, 393) while a bare root occupies 218 bytes. So the VM suite proves the scripts accept the new layout and nothing about whether a node accepts the cells or whether `price_floor` clears the new size; the only guards for that are arithmetic tripwires (core:918-929, codec.test.ts:102-122) and a live registration.

## Things the proposal misses

1. **The saving is not what users pay.** `price_floor` is a flat 300 CKB (core:90-92), enforced at type:274-278 and funded by the SDK as `max(300, minimum)` (codec:166-168, client:832). CKB's rule only sets the minimum; the 300 floor is what every name locks. Shrinking 218+n to 159+n frees nothing until the floor is lowered, and the floor's own justification (core:87-89, worst case 291 plus room) would need recomputing (new worst case 220). The "frees 20 CKB per name" framing in 37-id-redundancy.mjs is INFERRED to be about occupied size, not cost.
2. **A layout change is a redeploy, not an upgrade.** `AccountData::parse` (core:562-574) reads fixed offsets with no version field before byte 112, and inputs are never re-validated (type:63-65). An in-place type-id upgrade (08-upgrade.mjs:1-5) keeps the type hash, so existing 112-byte-header cells would be parsed at the new offsets. Every live name would be re-registered in a new namespace; "N x 20 CKB freed today" cannot happen for existing cells. All deployment constants, the drift vector (codec.test.ts:45-47) and gw/registry.ts's history scan move with it.
3. **The tripwires hard-code the type-args width** `(32 + 1 + 32)` at core:922-923 and codec:153.
4. **The fragile discriminator is kept.** Since a redeploy is forced anyway, a fixed version byte at offset 0 (1 CKB) would remove the dependence on "labels never start with 0x02" and make the next change an upgrade instead of another redeploy. Not shrinking, but the moment to do it.
5. **`next` and the id width must stay at 20.** Shrinking the id space to 16 bytes would make the T-3 griefing collision 2^64. The proposal correctly leaves them.
6. **Label into the witness** (keep id, drop the label from data) is the only field bigger than `id` for long names (up to 40 bytes), feasible on-chain (outputs' witnesses are readable, type:149-157; `require_parent` at :868 would match by id), but it costs the witness-free scans (codec:554-566, client:516-523, 639-642) one fetch per cell. For typical short labels change 1 is the better trade; noted, not recommended.

## Could not determine

- Whether the suite is currently green: not run.
- Cycle cost of deriving `id` per parse: not measured.
- Practical cost of a 2^80 blake2b collision over record-sized witnesses (change 5): not estimated beyond order of magnitude.
- Whether `price_floor` is meant to drop alongside (it decides whether any saving is real): the first opinion was not read, by instruction.
- Live testnet name count (to quantify what a redeploy re-registers): not queried.
- Whether any consumer outside this repository parses the layout: outside scope.
- Whether the request format's `ns` (request:297) should stay the full token hash: a design choice, either works if request:466 is kept consistent.
