# Open-Source Code Survey

This file records whether representative works in the paper provide public
implementation code. It is intended to support the appendix/source-checking
requirements of the course paper.

## Found Public Repositories

| Work | Public code found | Notes |
| --- | --- | --- |
| zk-creds | https://github.com/rozbb/zkcreds-rs | Rust library with Python wrapper examples. The GitHub page says it accompanies the zk-creds paper and contains benchmarks and passport examples. The repository was archived in 2025, but remains readable. |
| FIDO-AC | https://github.com/FIDO-AC/fidoac | Proof-of-concept implementation with Android app, FIDO server, FIDO-AC server, Rust ZKP code, Python mediator verification, and Docker Compose server setup. |
| Coconut | https://github.com/asonnino/coconut | Python implementation, Apache-2.0 license, installable as `coconut-lib`; depends on `petlib` and `bplib`. |
| Practical Delegatable Anonymous Credentials | https://github.com/docknetwork/crypto/tree/main/delegatable_credentials | The PoPETs paper points to this implementation path. |
| Hyperledger AnonCreds | https://github.com/hyperledger/anoncreds | Not one of the core papers, but useful as a real open-source anonymous credentials ecosystem. |

## No Official Repository Found During This Check

| Work | Result |
| --- | --- |
| EL PASSO | I found the paper and project descriptions, but did not find an obvious official author-maintained code repository. |
| IhMA | I found paper/ePrint metadata, but no obvious official implementation repository in the quick search. |
| Anonymous Credentials Light / concurrent-security revisit | I found papers/ePrint pages, but no obvious official implementation repository in the quick search. |

## Why This Local Project Does Not Vendor Those Repositories

The upstream implementations are valuable, but they are not ideal as a course
appendix experiment:

- zk-creds and FIDO-AC require Rust, Android, passport/eID data, or service
  orchestration;
- Coconut depends on pairing libraries that may be painful to install on a
  teacher's Windows machine;
- some works have no clear official code.

Therefore this directory provides a clean-room, dependency-free experiment that
checks the paper's design claims at the protocol-model level. The README states
its limitations explicitly.

