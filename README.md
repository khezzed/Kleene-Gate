# KleeneGate — 3-Valued Kleene Predicate Circuit with Active-Frontier Short-Circuit Pruning

**KleeneGate** (`contracts/kleene_gate.py`) is a GenLayer Intelligent Contract implementing arbitrary multi-level boolean and threshold predicate circuits (**`AND`**, **`OR`**, **`NOT`**, **`K_OF_N`**) over consensus-adjudicated evidence atoms using exact **Kleene 3-valued logic** (`UNKNOWN`, `TRUE`, `FALSE`), **dynamic active-frontier short-circuit pruning**, and **fail-closed negation**.

---

## 1. Overview & Motivation

Conditional releases, protocol upgrades, and multi-party authorizations rarely reduce to a flat checklist of items. Real operational policies require nested logical structure:
- **Fallback paths (`OR`)**: e.g., pass via a fast-track automated audit + formal proof (`AND`), *or* fall back to a `2-of-3` quorum of independent human reviews (`K_OF_N`).
- **Hard veto / disqualifier clauses (`NOT`)**: e.g., block deployment immediately if an emergency security bulletin confirms an active key compromise or critical exploit.
- **Short-circuit efficiency & safety**: once an upstream gate mathematically determines a subtree, evaluating redundant sibling atoms wastes validator compute and exposes the system to irrelevant state noise.
- **Fail-closed negation**: naive boolean negation (`not (atom == TRUE)`) dangerously treats missing, 404, or ambiguous evidence as a *passing* veto check.

**KleeneGate** solves all four problems deterministically on-chain while using GenVM validators strictly for narrow per-atom semantic evidence adjudication:
1. **Composable Circuit Grammar**: Sponsors freeze a verified acyclic formula DAG/tree combining `AND`, `OR`, `NOT`, and `K_OF_N` gates over commit-pinned evidence atoms.
2. **Exact Kleene 3-Valued Semantics**: Every unevaluated or `UNCLEAR` atom carries truth value `UNKNOWN`. Crucially, **`NOT(UNKNOWN) == UNKNOWN`** — unavailable, oversized, malformed, or prompt-injected evidence can never satisfy a `NOT` veto gate.
3. **Dynamic Active-Frontier Short-Circuit Pruning**: After every atom evaluation, deterministic code recomputes all gate values bottom-up and computes the exact set of still-pivotal (`active_frontier`) atoms reachable from the root solely through `UNKNOWN` gates. Any unevaluated atom outside the active frontier cannot affect the root under any future assignment and is deterministically pruned (`EXPECTED:ATOM_ALREADY_PRUNED`) before executing any web fetch or LLM call.
4. **Immediate Short-Circuit Finalization & Permissionless Expiry**: The instant `root_gate` transitions to `TRUE` or `FALSE`, the circuit finalizes immediately and credits the beneficiary or sponsor via pull-payment escrow. If the deadline passes while `root_gate` remains `UNKNOWN`, anyone can call `expire_circuit` to refund the sponsor (fail-closed).

---

## 2. Architecture & Formal Semantics

```text
                       [ G_ROOT: AND ]
                      /               \
            [ G_PATH: OR ]         [ G_NO_VETO: NOT ]
           /              \                 |
   [ G_FAST: AND ]   [ G_QUORUM: 2-of-3 ]  ( V_EXPLOIT )
      /       \        /       |       \
 (A_AUDIT) (A_FORMAL)(B_REV1)(B_REV2)(B_REV3)
```

### A. Kleene 3-Valued Gate Truth Rules
Every atom starts as `UNKNOWN (0)`. Consensus `HOLDS` maps to `TRUE (1)`, `CONTRADICTED` maps to `FALSE (2)`, and `UNCLEAR` remains `UNKNOWN (0)`.

| Gate Operator | Evaluates `TRUE (1)` | Evaluates `FALSE (2)` | Otherwise |
| :--- | :--- | :--- | :--- |
| **`NOT(x)`** | `x == FALSE` | `x == TRUE` | **`UNKNOWN`** *(fail-closed)* |
| **`AND(c_1..c_m)`** | All children `TRUE` | Any child `FALSE` *(short-circuit)* | `UNKNOWN` |
| **`OR(c_1..c_m)`** | Any child `TRUE` *(short-circuit)* | All children `FALSE` | `UNKNOWN` |
| **`K_OF_N(k; c_1..c_m)`** | `count(TRUE) >= k` *(short-circuit)* | `count(TRUE) + count(UNKNOWN) < k` *(unreachable quorum)* | `UNKNOWN` |

### B. Dynamic Active-Frontier Pruning Theorem
An unevaluated atom $a$ lies in `active_frontier` if and only if there exists at least one directed path from `root_gate_id` to $a$ whose every gate currently has Kleene value `UNKNOWN` (and $a$ has not reached `MAX_ATOM_ATTEMPTS`).
- If `A_AUDIT` evaluates `FALSE`, `G_FAST = AND(A_AUDIT, A_FORMAL)` immediately flips to `FALSE`, removing `A_FORMAL` from the active frontier. Calling `evaluate_atom(..., "A_FORMAL")` reverts deterministically with `EXPECTED:ATOM_ALREADY_PRUNED` and **zero** validator web/LLM calls.
- If a DAG atom is shared by both a short-circuited gate and a still-`UNKNOWN` gate, top-down reachability keeps that atom on `active_frontier` until all paths through it are decided.
- Exhausted `UNCLEAR` atoms (`attempts == MAX_ATOM_ATTEMPTS = 2`) are tracked separately from structurally pruned atoms and revert with `EXPECTED:ATOM_MAX_ATTEMPTS_REACHED`.

### C. Consensus Boundary & Exact Canonical Equality
- **Storage Snapshotting**: All inputs (`circuit_id`, `atom_id`, `evidence_url`, `claim`, `claim_sha256`) are snapshotted into local variables prior to `gl.vm.run_nondet_unsafe(leader_fn, validator_fn)` (zero `self` references inside closures).
- **Fail-Closed Fetch Bounds**: Leader and validators independently fetch raw bytes via `gl.nondet.web.get(url)` enforcing HTTP `200` only, redirects disallowed (`301/302/307/308`), raw length within `[32, 16384]` bytes, and strict UTF-8 decoding. Any failure maps deterministically to `verdict = "UNCLEAR"`.
- **Prompt-Injection Firewall & Verbatim Grounding**: Evidence bytes are isolated inside `<UNTRUSTED_EVIDENCE>` delimiters. The LLM classifies strictly into `{"HOLDS", "CONTRADICTED", "UNCLEAR"}`. Both `HOLDS` and `CONTRADICTED` require an exact verbatim substring quote (`12..240` chars) present character-for-character in the raw payload; otherwise the verdict is downgraded to `UNCLEAR`.
- **Exact 7-Field Canonical Envelope**: Leader and validator canonicalize to the exact 7-field dictionary:
  ```json
  {
    "circuit_id": "REL-PASS",
    "atom_id": "A_AUDIT",
    "claim_sha256": "<sha256>",
    "http_status": 200,
    "fetch_status": "OK",
    "evidence_sha256": "<sha256>",
    "verdict": "CONTRADICTED"
  }
  ```
  Every single returned and stored field is compared for **100% exact equality** (`leader_env == val_env`). Zero unchecked rationale text is stored.

### D. Conservation of Funds & Circuit Lifecycle
- **Lifecycle States**:
  - `0` — `CIRCUIT_UNDECIDED`: active, evaluating frontier atoms.
  - `1` — `CIRCUIT_DECIDED_TRUE`: terminal; escrow credited to `withdrawable[beneficiary]`.
  - `2` — `CIRCUIT_DECIDED_FALSE`: terminal; escrow credited to `withdrawable[sponsor]`.
  - `3` — `CIRCUIT_EXPIRED_REFUNDED`: terminal; permissionlessly expired past `deadline_ts`, escrow refunded to `withdrawable[sponsor]`.
  - `4` — `CIRCUIT_CANCELLED`: terminal; cancelled by sponsor strictly before any atom evaluation (`atoms_evaluated_count == 0`).
- **Exact Accounting Invariant** (asserted on every state-mutating transaction):
  $$\text{total\_deposited\_wei} - \text{total\_withdrawn\_wei} = \text{total\_locked\_wei} + \text{total\_withdrawable\_wei}$$

---

## 3. Contract Interface

### Write Methods
- `create_circuit(circuit_id: str, beneficiary: str, duration_seconds: u256, circuit_spec_json: str)` *(payable)*: Locks `gl.message.value`, validates circuit topology (acyclic 3-color DFS, max depth $\le 6$, full reachability, unique IDs, distinct gate children, unique `(evidence_url, claim)` pairs, 40-hex commit-SHA GitHub pinning), and stores the circuit.
- `evaluate_atom(circuit_id: str, atom_id: str)` *(permissionless)*: Verifies atom is on `active_frontier`, runs multi-validator consensus, recomputes Kleene gates bottom-up, prunes short-circuited subtrees, and immediately finalizes if `root_gate` becomes decided.
- `cancel_circuit(circuit_id: str)` *(sponsor-only, pre-evaluation)*: Refunds escrow to sponsor strictly before any atom evaluation starts (`atoms_evaluated_count == 0`).
- `expire_circuit(circuit_id: str)` *(permissionless)*: Finalizes an `UNDECIDED` circuit past `deadline_ts` and credits sponsor refund.
- `withdraw()`: Pull-payment native transfer (`emit_transfer`) of caller's settled or refunded balance using Checks-Effects-Interactions.

### View Methods
- `get_circuit(circuit_id: str)`: Returns full circuit metadata, status, root Kleene value, per-gate Kleene values, per-atom verdicts/digests, `active_frontier`, and `pruned_atoms`.
- `get_atom(circuit_id: str, atom_id: str)`: Returns full atom details and `is_in_active_frontier`.
- `get_accounting_state()`: Returns all 4 conservation counters, `circuit_count`, and `conservation_ok`.
- `get_withdrawable_balance(account: str)`: Returns withdrawable balance for an address.

---

## 4. Repository Structure

```text
Kleene-Gate/
├── contracts/
│   ├── kleene_gate.py                         # Main KleeneGate contract (LF, pinned runner)
│   └── probe_runner.py                        # Minimal pre-flight StudioNet runner probe
├── fixtures/
│   └── evidence/
│       ├── audit_failed.json                  # 349 B — FAILED security audit (A_AUDIT -> FALSE)
│       ├── formal_spec_unused.json            # 271 B — Never evaluated (pruned by G_FAST=FALSE)
│       ├── review_alpha_pass.json             # 356 B — Reviewer Alpha APPROVED (B_REV1 -> TRUE)
│       ├── review_beta_pass.json              # 362 B — Reviewer Beta APPROVED (B_REV2 -> TRUE)
│       ├── review_gamma_unused.json           # 276 B — Never evaluated (pruned by 2-of-3=TRUE)
│       ├── security_clean.json                # 362 B — Zero active exploit (V_EXPLOIT -> FALSE => NOT=TRUE)
│       ├── security_compromise.json           # 377 B — Active compromise (V_EXPLOIT -> TRUE => NOT=FALSE)
│       └── security_ambiguous_injection.json  # 322 B — Off-topic log + prompt injection (UNCLEAR => NOT=UNKNOWN)
├── scripts/
│   └── deploy_and_demo_studionet.py           # End-to-end StudioNet probe, deploy & live demo runner
├── tests/
│   └── direct/
│       ├── conftest.py                        # Deterministic GenVM mock harness w/ adversarial leader hook
│       ├── test_circuit_validation.py         # Cycles, depth, orphans, sybil pairs, URL pinning, bounds
│       ├── test_kleene_semantics_and_pruning.py # Truth tables, active-frontier pruning, shared DAG, veto, expiry
│       └── test_adversarial_and_accounting.py # 9 leader-forgery attacks, 9 HTTP/byte failures, auth, conservation
├── gltest.config.yaml
├── pyproject.toml
├── requirements.txt
├── release_manifest.json                      # Machine-readable live StudioNet proof manifest
└── README.md
```

---

## 5. Local Verification & Test Suite

```bash
genvm-lint check contracts/kleene_gate.py --json
# {"ok":true,"lint":{"ok":true,"passed":3},"validate":{"ok":true,"contract":"KleeneGate","methods":9,"view_methods":4,"write_methods":5,"ctor_params":1}}

genvm-lint typecheck contracts/kleene_gate.py
# ✓ No type errors found

pytest tests/direct/ -v
# 35 passed in 0.21s
```

---

## 6. Live Testnet Deployment & On-Chain Proof (GenLayer StudioNet)

- **Network**: GenLayer StudioNet (`Chain ID 61999`, RPC `https://studio.genlayer.com/api`)
- **Pre-Flight Probe Contract**: [`0xf3385681906f6cc8a9c8b3A516A6Df422577B8F4`](https://explorer-studio.genlayer.com/address/0xf3385681906f6cc8a9c8b3A516A6Df422577B8F4)
- **KleeneGate Contract Address**: [`0x9522F74765b9f7aC3Baeee56d9aDd0fCb4219Ff6`](https://explorer-studio.genlayer.com/address/0x9522F74765b9f7aC3Baeee56d9aDd0fCb4219Ff6)
- **Deployed Commit SHA**: [`11ad896b4fbe929f9fbaf418e8e6ad22901c0eaf`](https://github.com/khezzed/Kleene-Gate/commit/11ad896b4fbe929f9fbaf418e8e6ad22901c0eaf)
- **Pinned Contract Source**: [`contracts/kleene_gate.py`](https://github.com/khezzed/Kleene-Gate/blob/11ad896b4fbe929f9fbaf418e8e6ad22901c0eaf/contracts/kleene_gate.py) (Git blob `e9ddd120dfdec5f1cc1fc471a87fb4b55c09ecd0`, `50,705` bytes, LF)
- **Full Release Manifest**: [`release_manifest.json`](release_manifest.json)

### Complete Live StudioNet Transaction Log (25 / 25 Finalized)

| Step | Action | Transaction Hash | Status | Leader Result | Verified On-Chain Outcome |
| :---: | :--- | :--- | :---: | :---: | :--- |
| **P1** | Deploy `ProbeRunner` | [`0xb130...9d2c`](https://explorer-studio.genlayer.com/transactions/0xb1304875b055e5fca7aa2fa472eefbc01fee00b61458841e2d1f112ce5e89d2c) | `FINALIZED` | `SUCCESS` | Runner pre-flight contract deployed |
| **P2** | `ProbeRunner.ping` | [`0x3ec8...fab3`](https://explorer-studio.genlayer.com/transactions/0x3ec8e250c5cbb6b7fce40b0a2bbd5c03939d37cd259153ff07111093bbf6fab3) | `FINALIZED` | `SUCCESS` | Read-back verified: `counter == 1, last_tag == "kleene-gate-preflight"` |
| **D1** | Deploy `KleeneGate` | [`0x9ed4...a20a`](https://explorer-studio.genlayer.com/transactions/0x9ed4fc4894a6c73bcd7930aa257191502fb8afbb6c797bdd77b8b42bcbe8a20a) | `FINALIZED` | `SUCCESS` | Byte-identical LF source deployed (`conservation_ok == True`) |
| **S1** | `create_circuit(REL-PASS)` | [`0xb768...9d00`](https://explorer-studio.genlayer.com/transactions/0xb7684e897caaa0e7497da5c494bb1fbb1fa67b27e53f35f9eacd544b723c9d00) | `FINALIZED` | `SUCCESS` | Escrowed `100` wei; 6 atoms, 5 nested gates (`AND`/`OR`/`NOT`/`2-of-3`) |
| **S2** | `evaluate_atom(REL-PASS, A_AUDIT)` | [`0xb411...3f76`](https://explorer-studio.genlayer.com/transactions/0xb4116f34db92f788e5a8e10382be8edbe3e62c6f29bfb94ae4e09105e0483f76) | `FINALIZED` | `SUCCESS` | Consensus `CONTRADICTED` $\implies$ `G_FAST = FALSE`, `A_FORMAL` pruned |
| **G1** | `evaluate_atom(REL-PASS, A_FORMAL)` | [`0xb076...f68f`](https://explorer-studio.genlayer.com/transactions/0xb076d9176223aa71f8d872ab8654968be92d3bede7e4b385cd959a4a066af68f) | `FINALIZED` | `ERROR` | `EXPECTED FAILURE`: `EXPECTED:ATOM_ALREADY_PRUNED` (`eq_outputs: 0`) |
| **S3** | `evaluate_atom(REL-PASS, B_REV1)` | [`0xda54...bd5d`](https://explorer-studio.genlayer.com/transactions/0xda54ef61e6ad0e63e004b2dd7c7cd73044acdcddec4c03b00b9a4bb62153bd5d) | `FINALIZED` | `SUCCESS` | Consensus `HOLDS` (`1/2` toward `G_QUORUM`) |
| **S4** | `evaluate_atom(REL-PASS, B_REV2)` | [`0x976f...6a97`](https://explorer-studio.genlayer.com/transactions/0x976f2e143211c3b79ee66fbafd409babb78c80b656483b25bda060bfa2956a97) | `FINALIZED` | `SUCCESS` | Consensus `HOLDS` $\implies$ `G_QUORUM = TRUE`, `G_PATH = TRUE`, `B_REV3` pruned |
| **G2** | `evaluate_atom(REL-PASS, B_REV3)` | [`0x0ecb...b246`](https://explorer-studio.genlayer.com/transactions/0x0ecb92a535997a00c33b0f7906fa1f95d4df5c92c86780cac175652d5635b246) | `FINALIZED` | `ERROR` | `EXPECTED FAILURE`: `EXPECTED:ATOM_ALREADY_PRUNED` (`eq_outputs: 0`) |
| **G3** | Beneficiary `withdraw()` early | [`0x0c9d...1559`](https://explorer-studio.genlayer.com/transactions/0x0c9d7f980207f424fc3c669ab3f77a2f8fdf34dbaa5256ee93c512ced4cd1559) | `FINALIZED` | `ERROR` | `EXPECTED FAILURE`: `EXPECTED:NOTHING_TO_WITHDRAW` (`NOT(V_EXPLOIT)` still `UNKNOWN`) |
| **G4** | Sponsor `cancel_circuit(REL-PASS)` | [`0x2089...4389`](https://explorer-studio.genlayer.com/transactions/0x20892c577bbfa1d1e9824bd889e31017ad4d770b0f4ef26cd7c8c1e5f1aa4389) | `FINALIZED` | `ERROR` | `EXPECTED FAILURE`: `EXPECTED:CIRCUIT_EVALUATION_STARTED` (anti-rugpull guard) |
| **S5** | `evaluate_atom(REL-PASS, V_EXPLOIT)` | [`0xa56c...43ab`](https://explorer-studio.genlayer.com/transactions/0xa56c61c389fe6bc9cf826816be93bb711f564606b295998e47d98b7b939943ab) | `FINALIZED` | `SUCCESS` | Consensus `CONTRADICTED` $\implies$ `NOT(FALSE)=TRUE` $\implies$ `DECIDED_TRUE` (4 eval, 2 pruned) |
| **S6** | Beneficiary `withdraw()` | [`0x042c...76de`](https://explorer-studio.genlayer.com/transactions/0x042c08bc52dcf5f7d813bf1ababd608c996d1eafc0e09f090783fc324ee576de) | `FINALIZED` | `SUCCESS` | Beneficiary pulled `100` wei via `emit_transfer` |
| **S7** | `create_circuit(REL-VETO)` | [`0x505a...ee8a`](https://explorer-studio.genlayer.com/transactions/0x505a27fdee379fd762eae13f73085c14563aac1c34423b3a9eefbac64247ee8a) | `FINALIZED` | `SUCCESS` | Escrowed `80` wei for early-veto test |
| **G5** | Stranger `cancel_circuit(REL-VETO)` | [`0x7d51...b1c`](https://explorer-studio.genlayer.com/transactions/0x7d51cdb73d3cb1cc458985b548cd8fbd0a5778a7afdae4e6979c6f84e4914b1c) | `FINALIZED` | `ERROR` | `EXPECTED FAILURE`: `EXPECTED:UNAUTHORIZED_CALLER` |
| **S8** | `evaluate_atom(REL-VETO, V_EXPLOIT)` | [`0xf35d...90f2`](https://explorer-studio.genlayer.com/transactions/0xf35dcf6617e8a5ca5eeb2445187bf663116f908c800411e5767d5f1e933190f2) | `FINALIZED` | `SUCCESS` | Consensus `HOLDS` $\implies$ `NOT(TRUE)=FALSE` $\implies$ `DECIDED_FALSE` immediately (5 atoms pruned) |
| **G6** | `evaluate_atom(REL-VETO, B_REV1)` | [`0x72a4...b4e6`](https://explorer-studio.genlayer.com/transactions/0x72a4a27a77976f8b76ee747105a5cfeb9d5efc5bf431d5f4ff727ad3b86cb4e6) | `FINALIZED` | `ERROR` | `EXPECTED FAILURE`: `EXPECTED:CIRCUIT_ALREADY_FINAL` |
| **S9** | `create_circuit(REL-FAILCLOSED)` | [`0xd1e6...8aea`](https://explorer-studio.genlayer.com/transactions/0xd1e6c72ff5760fb9e853042eba4b0da5d60411259d81a1a0ef288cb5a34d8aea) | `FINALIZED` | `SUCCESS` | Escrowed `60` wei (`duration = 150s`, `AND(B_REV1, NOT(V_EXPLOIT))`) |
| **S10** | `evaluate_atom(REL-FAILCLOSED, B_REV1)` | [`0xa19d...23de`](https://explorer-studio.genlayer.com/transactions/0xa19d15fbfaa1716715ca009a962fc44ed9cb3b28f38c4975181eaee7a2af23de) | `FINALIZED` | `SUCCESS` | Consensus `HOLDS` (`TRUE`) |
| **S11** | `evaluate_atom(REL-FAILCLOSED, V_EXPLOIT)` | [`0xbf7a...c60c`](https://explorer-studio.genlayer.com/transactions/0xbf7aedaab3162e5a7d7c01299b58195790b1b209c73987fcb1d8a117507ac60c) | `FINALIZED` | `SUCCESS` | Prompt-injected off-topic log $\to$ `UNCLEAR` $\implies$ `NOT(UNKNOWN)=UNKNOWN` (fail-closed) |
| **G7** | `create_circuit` w/ cycle `G1->G2->G1` | [`0xbc5a...c5a`](https://explorer-studio.genlayer.com/transactions/0xbc5a3d526451bc0cf458eeab45102f2c6f293822f7724bbdf91eb5d4a4b97c5a) | `FINALIZED` | `ERROR` | `EXPECTED FAILURE`: `EXPECTED:CIRCUIT_CYCLE_DETECTED` |
| **G8** | `create_circuit` w/ mutable `/main/` URL | [`0x3eea...ff0f`](https://explorer-studio.genlayer.com/transactions/0x3eea08a7d8986329b0a3801d348f56bac036631430d49171572c490960faff0f) | `FINALIZED` | `ERROR` | `EXPECTED FAILURE`: `EXPECTED:UNPINNED_GITHUB_URL` |
| **G9** | Replay `evaluate_atom(REL-PASS, A_AUDIT)` | [`0x8fcc...a935`](https://explorer-studio.genlayer.com/transactions/0x8fccc3cd63a9a3d188d65514f134bfa3d33745c368dafaaecf6bf7cc0157a935) | `FINALIZED` | `ERROR` | `EXPECTED FAILURE`: `EXPECTED:CIRCUIT_ALREADY_FINAL` |
| **S12** | `expire_circuit(REL-FAILCLOSED)` | [`0x85ef...978`](https://explorer-studio.genlayer.com/transactions/0x85efcac8829e58d7210aeb64b6c0dc91232c8ca3facd2096d637e74510f8f978) | `FINALIZED` | `SUCCESS` | Permissionless expiry past deadline $\implies$ `EXPIRED_REFUNDED` (`60` wei to Sponsor) |
| **S13** | Sponsor `withdraw()` | [`0x050a...a048`](https://explorer-studio.genlayer.com/transactions/0x050a6002f38c5d6cbe08634991b1ec109f5ffa1c75427865e45825cf718ea048) | `FINALIZED` | `SUCCESS` | Sponsor pulled `140` wei (`80 + 60`); final read-back: `deposited=240, withdrawn=240, locked=0, withdrawable=0, conservation_ok=True` |
