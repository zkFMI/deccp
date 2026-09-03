# DeCCP — Decentralized Central Counterparty

DeCCP is a **Decentralized Central Counterparty**. “Central” describes the
logical novation and risk function; “decentralized” describes who controls and
verifies that function. Material state changes require signatures from a
threshold authority set rather than one operator.

## Boundary

- DeKYX verifies who may participate and returns a scoped subject-line proof.
- DeCCP admits clearing members; records DeFMI-backed collateral references;
  sets initial/variation margin; accepts obligations; computes deterministic
  multilateral netting; manages guarantee capacity and holds; freezes defaults;
  and applies the loss waterfall.
- zkPI carries the typed executable instructions created from a DeCCP netting or
  default-settlement context.
- DeFMI owns the authoritative cash, security, collateral lock, and settlement
  records. DeCCP stores only immutable DeFMI identifiers and receipts.
- Aethel owns payment-stream and receivable semantics. `deccp-aethel` translates
  an Aethel guarantee offer into a DeCCP reservation and later binds, releases,
  or consumes it.

Incoming clearing obligations require an `InstructionPort` verification; a
non-zero `zkpi_digest` alone is not accepted as proof. Outgoing netting legs
carry an exact instruction-context digest, while DeFMI remains responsible for
executing and finalizing the resulting instruction.

This directory is a standalone, locked Rust workspace rather than a crate added
to QOMM or DeKYX. The enclosing TradFi repository ignores new `mvp/*` projects.
`mvp/qomm/rust/qomm-harness/src/bin/export_repos.rs` publishes it as the
`deccp` repository under the shared MIT `LICENSE` (the workspace manifest
declares MIT to match); `defmi` takes it as a Git dependency. No nested Git
history or remote is created here.

## What every path requires

| Path | Quorum approval | DeKYX | zkPI (`InstructionPort`) | DeFMI (`DeFmiPort`) |
|---|---|---|---|---|
| CCP capitalization | — | — | — | capital lock verified |
| Member admission | yes | eligibility verified, one member per subject line | — | default-fund lock verified |
| Collateral lot | — | — | — | lock verified, lock ids unique across capital, funds, and lots |
| Margin update | yes | — | — | — |
| Cycle open / close | yes | — | — | — |
| Obligation | — | — | verified before netting | — |
| Cycle settlement | — | — | — | receipt for the exact proposal digest |
| Guarantee facility | yes | — | — | facility verified; guarantor must be an active member |
| Guarantee reservation | — | — | — | hold verified; guarantor still active; CAS on sequence (and state digest for confidential facilities) |
| Guarantee release / claim | — | — | — | receipt for the exact context; claim refused on an expired hold |
| Default declaration | yes | — | — | — |
| Default resolution | yes | — | — | receipt for the exact waterfall context |

Netting modes: **Gross-Gross** keeps every leg and debits gross risk per
payer; **Gross-Net** nets only the cycle's settlement asset; **Net-Net** nets
every asset. Every net position is conserved per asset and every net risk
debit must fit inside the participant's encumbered margin, or `prepare_close`
refuses.

## Confidential Aethel guarantees

The generic clearing API supports public-value capacity for venues whose risk
state is transparent. Aethel uses a separate confidential path: DeCCP stores a
coverage commitment and a DeFMI state digest, never a plaintext guarantee
amount. Reservations, releases, and claims are compare-and-swap transitions on
the prior state digest and sequence. A DeFMI adapter must verify the hidden
amount relation, capacity bound, transition proof, and final receipt before
DeCCP advances either state. This preserves Aethel's existing
`coverage_commitment` boundary and prevents concurrent holds from spending the
same hidden remaining capacity.

`deccp-aethel` exposes `reserve`, `bind_issuance`, `release`, and `claim`. Its
request and record types carry no amount, capacity, reserved, or consumed
field, and the adapter tests assert that the DeCCP records it produces contain
only commitments, digests, identifiers, and timestamps. The adapter does not
depend on `aethel-core`; an application composes the two.

## Persistence boundary

Default-waterfall balances are changed only after both threshold approval and a
DeFMI receipt for the exact settlement context. `ClearingBook` is deliberately
not directly deserializable because that would bypass quorum, DeKYX, and DeFMI
checks. Two recovery routes exist:

- replay the verified operations; or
- `ClearingBook::snapshot()` → `ClearingSnapshot` (plain data, canonical
  digest) → `ClearingBook::restore(trusted_authorities, snapshot, approval)`,
  which requires the trusted authority set to equal the snapshot's, a quorum
  approval of the snapshot digest, and every structural invariant
  (`ClearingBook::validate`): key/id agreement, one margin account per member,
  unique subject lines and DeFMI locks, facility `reserved`/`consumed` equal to
  the sum of live and consumed holds, hold status/exposure/receipt shape,
  cycle status/proposal/receipt shape, and default-case shape; or
- `ClearingBook::restore_authenticated(snapshot)` for a host whose store is
  itself authenticated, such as a consensus-committed VM state whose root
  commits to the snapshot bytes. It skips the separate quorum signature and
  nothing else: the same invariants run, so a tampered snapshot still fails
  closed. Storage the host does not authenticate must use `restore`.

## Why this is not a second DeFMI

The prior integrated implementation already separated confidential credit and
waterfall arithmetic from settlement, but placed those reusable modules under
the DeFMI package and placed guarantee lifecycle in Aethel. This extraction does
not copy a ledger. DeCCP retains only clearing/risk state and references the
authoritative DeFMI facility hold or settlement receipt.

## Aethel cutover status

Both Aethel paths are cut over. Identity goes through DeKYX; guarantee
capacity goes through this crate. The Avalanche VM in `mvp/qomm` holds a
`ClearingBook` in its consensus state (`State::deccp`, persisted as a
`ClearingSnapshot` and rebuilt with `restore_authenticated`) and drives it
through `AethelDeCcpAdapter`:

| VM transaction | DeCCP operation | Evidence the VM `DeFmiPort` verifies |
|---|---|---|
| `issueDeccpClearingBook` | `ClearingBook::new` | CCP capital: a cash note locked under the capital tag, proof digest = its value commitment |
| `issueDeccpMember` | `admit_participant` | DeKYX presentation for the clearing-membership scope (the `EligibilityPort`); default fund: a cash note locked under the member's tag |
| `issueDeccpGuaranteeFacility` | `register_confidential_guarantee_facility` | the DeFMI credit facility of the guarantor's DeFMI guarantor id, its cap and beneficiary commitments, and the initial state digest derived from them |
| `issueAethelGuarantee` | `reserve` | the live DeFMI hold for the coverage commitment; after-state = H(previous, reserve, hold, commitment, DeFMI sequence) |
| `issueAethelReceivable` | `bind_issuance` | Aethel's own issuance checks and the zkPI |
| `issueAethelGuaranteeRelease` | `release` | the DeFMI hold released with the named settlement digest |
| `issueAethelGuaranteeClaim` | `claim` | the DeFMI hold consumed with the claim's settlement digest, plus the zkPI |

DeCCP records the Aethel provider id as the member id, the DeFMI participant
id as the settlement participant, and the DeKYX subject line as the only
identity fact. The plaintext capital and default-fund figures are DeCCP's own
waterfall parameters, quorum-approved and backed by a live DeFMI lock the VM
cannot open; the Aethel guarantee path never draws on them. Public-value
facilities, collateral lots, netting cycles, and the default waterfall are not
offered by that host; its `DeFmiPort` refuses them.

## Verification

All tests, Clippy, formatting, and builds run on an approved remote Linux
worker; the local Mac is for reading, editing, and `cargo fmt`. The latest run
(OmenX, Rust 1.97.1, after `restore_authenticated` was added): 7 core and 3
adapter integration tests passed, warning-denied Clippy passed, formatting
passed, optimized release build passed. The 1.85.1 MSRV `--locked` run dates
from the previous revision; the test container carries only 1.97.1.
