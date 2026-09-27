# .cell milestones

Updated 2026-09-27

What has shipped for .cell names on CKB, newest first. Each entry says what happened, when, and where to check it. Only finished work is listed.

## 2026-09-26: CCC resolves names, in @ckb-ccc/core 1.23.0

CCC, the ckb-devrel TypeScript SDK for CKB, now lets an app resolve names and other representations through `Address.fromString`. We asked for it in [issue #548](https://github.com/ckb-devrel/ccc/issues/548) and wrote [PR #575](https://github.com/ckb-devrel/ccc/pull/575). Hanssen0, the CCC maintainer, shaped the final design in review, merged it and released it the same day ([changelog](https://github.com/ckb-devrel/ccc/blob/master/packages/core/CHANGELOG.md), [npm](https://www.npmjs.com/package/@ckb-ccc/core)).

- The hook is neutral: an app sets an `AddressResolver` on its client, and CCC ships no resolver of its own. It works for .cell, .bit or any other naming system.
- The CCC docs describe it on the Address concepts page, in English and Chinese.
- Nothing resolves .cell through CCC until our resolver is published in cellula-sdk.

## 2026-09-25: .cell in ckbadger

Jan Xie added .cell support to [ckbadger](https://github.com/janx/ckbadger), his local-first CKB explorer, two days after we asked in [issue #14](https://github.com/janx/ckbadger/issues/14). .cell sits next to .bit and did:ckb as an identity standard there ([commit 87cab244](https://github.com/janx/ckbadger/commit/87cab2440d07dd71f782061486205147494f9c3a)):

- the four Cells scripts catalogued on mainnet and testnet, each version hash checked against the chain
- names parsed from their data and witness, including sub-names and sale state
- a page per name, plus search
- a name transfer shown in the recipient's activity stream

## 2026-09-25: Explore from the resolver, and cellula-sdk 0.1.9

Explore on testnet reads names a page at a time from the resolver's `/directory` route, instead of reading every name's records in the browser. Every row carries the outpoint it was read at, and a name's own page still reads the chain.

[cellula-sdk 0.1.9](https://www.npmjs.com/package/cellula-sdk/v/0.1.9) gives the same pattern to anyone listing names: `liteList()`, `hydrateMany()` and `payMethodsOf()`. The public resolver serves `/directory` too ([commit 3788e834](https://github.com/LusoCryptoLabs/cells-resolver/commit/3788e8347c5b31fd9c0f763441f3f6dd0081813a)).

## 2026-09-23: the contracts and the resolver are public

- [cells-contracts](https://github.com/LusoCryptoLabs/cells-contracts), MIT: the four scripts behind .cell names. CI rebuilds the mainnet binaries and compares their hashes with the code cells on chain, and [cellula.id/api/verify](https://cellula.id/api/verify) does the same check live.
- [cells-resolver](https://github.com/LusoCryptoLabs/cells-resolver), MIT: the HTTP API as it runs at cellula.id. `docker run -e CKB_NETWORK=mainnet -p 8787:8787 cells-resolver` is a complete second instance.
- Announced on [Nervos Talk](https://talk.nervos.org/t/cellula-id-cell-names-on-ckb-with-the-contracts-public-and-reproducible/10753).

## 2026-09-21: mainnet opens

Registration opened at 11:15 UTC. By 26 September, 13 names outside the reserved list had been registered, each publishing a CKB payout address.

## 2026-09-13: owned from a Bitcoin or an Ethereum key, on testnet

A name's owner is a lock hash, so any CKB lock can own one. Through Omnilock, a Bitcoin key registered `paulo.cell` and edited its records, and an Ethereum key did the same for `david.cell`. Each is an ordinary CKB transaction, with no Bitcoin or Ethereum transaction behind it. On Pudge:

- register `paulo.cell`: `0x77929d314616b5073cbaf8274b2168cde3e1f0c459024ed6e8ed5d305865285f`
- edit `paulo.cell`: `0x9c07cd1105fd5f246446eb2ec39497fa13213e04f17b69389b4c146d6a634ba8`
- register `david.cell`: `0x7c435bed538944711a693cee0b9ed7d19bc9ee4641f7ff764bbd85e4971583fd`
- edit `david.cell`: `0x034a8dfb66d3b8117e1e04b275e151bd04538ba61d12d22bc4eed5056003edda`

## 2026-09-04: paid by name over Fiber, on testnet

`telmo.cell` published its Fiber node as a record (`0xba70f36da3101ef7439fbc417351f714ca04bcc629d37d481808764446a713a1`, Pudge block 22301240). A node with no channel to it read the record and paid it 4.56 CKB through a public hub. The 0.1% fee shows the payment was forwarded. The namespace used then was replaced on 4 September. The record format is unchanged, and no name publishes a Fiber node today.

## Longer write-ups

- [A name you can be paid at](https://scryvehq.com/article/a-name-you-can-be-paid-at-muekrwzx), on Scryve: what a .cell name is for.
- [The launch post](https://talk.nervos.org/t/cellula-id-cell-names-on-ckb-with-the-contracts-public-and-reproducible/10753), on Nervos Talk: how the contracts work, and what is public.
