# KleeneGate — 3-Valued Kleene Predicate Circuit with Possibility-Interval Pruning

**KleeneGate** (`contracts/kleene_gate.py`) is a GenLayer Intelligent Contract implementing arbitrary multi-level boolean and threshold predicate circuits (**`AND`**, **`OR`**, **`NOT`**, **`K_OF_N`**) over consensus-adjudicated evidence atoms using exact **Kleene 3-valued logic** (`UNKNOWN`, `TRUE`, `FALSE`), **3-valued possibility-interval propagation** (`can_be_true`, `can_be_false`), **dynamic active-frontier short-circuit pruning**, and **fail-closed negation**.

---

## 1. Overview & Motivation

Conditional releases, protocol upgrades, and multi-party authorizations rarely reduce to a flat checklist of items. Real operational policies require nested logical structure:
- **Fallback paths (`OR`)**: pass via an automated security audit + formal proof (`AND`), *or* fall back to a `2-of-3` quorum of independent human reviews (`K_OF_N`).
- **Hard veto / disqualifier clauses (`NOT`)**: block release immediately if an incident response bulletin confirms an active signing-key compromise or critical exploit.
- **Short-circuit efficiency & safety**: once an upstream gate mathematically determines a subtree — or once exhausted `UNCLEAR` atoms render a threshold quorum unreachable — evaluating redundant sibling atoms wastes validator compute and exposes the workflow to irrelevant state noise.
- **Fail-closed negation**: naive boolean negation (`not (atom == TRUE)`) dangerously treats missing, 404, ambiguous, or prompt-injected evidence as a *passing* veto check.

**KleeneGate** solves all four problems deterministically on-chain while constraining GenVM validators strictly to narrow per-atom semantic adjudication over unstructured external prose:
1. **Composable Circuit Grammar**: Sponsors freeze a verified acyclic formula DAG/tree combining `AND`, `OR`, `NOT`, and `K_OF_N` gates over commit-pinned evidence atoms.
2. **Exact Kleene 3-Valued Semantics**: Every unevaluated or `UNCLEAR` atom carries truth value `UNKNOWN`. Crucially, **`NOT(UNKNOWN) == UNKNOWN`** — unavailable, oversized, malformed, or prompt-injected evidence can never satisfy a `NOT` veto gate.
3. **Sound Possibility-Interval Propagation (`CIRCUIT_UNSATISFIABLE`)**: Each node tracks both its exact Kleene value and its reachability bounds `(can_be_true, can_be_false)`, distinguishing still-evaluable `UNKNOWN` atoms (`attempts < 2`) from permanently exhausted `UNKNOWN` atoms (`attempts == 2`, `can_t = False, can_f = False`). Because internal Kleene values never collapse `UNKNOWN` to `FALSE`, negation remains 100% fail-closed under arbitrary `NOT` nesting (`NOT(K_OF_N(...))`), while any circuit whose root satisfies `not can_be_true(root)` transitions immediately to `CIRCUIT_UNSATISFIABLE`, pruning all remaining atoms and refunding the sponsor without waiting for expiry.
4. **Dynamic Active-Frontier Short-Circuit Pruning**: After every atom evaluation, deterministic code computes the exact set of still-pivotal (`active_frontier`) atoms reachable from `root_gate_id` solely through `UNKNOWN` gates that can still transition. Any unevaluated atom outside the active frontier cannot affect the root under any future assignment and reverts deterministically (`EXPECTED:ATOM_ALREADY_PRUNED`) with zero web fetches or LLM calls.

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

### A. Kleene 3-Valued Gate & Possibility-Interval Rules
Every atom starts as `UNKNOWN (0)`. Consensus `HOLDS` maps to `TRUE (1)`, `CONTRADICTED` maps to `FALSE (2)`, and `UNCLEAR` remains `UNKNOWN (0)`.

| Gate Operator | Kleene `TRUE (1)` | Kleene `FALSE (2)` | `can_be_true` | `can_be_false` |
| :--- | :--- | :--- | :--- | :--- |
| **`NOT(x)`** | `x == FALSE` | `x == TRUE` | `can_f(x)` | `can_t(x)` |
| **`AND(c_1..c_m)`** | All children `TRUE` | Any child `FALSE` | `all(can_t)` | `any(can_f)` |
| **`OR(c_1..c_m)`** | Any child `TRUE` | All children `FALSE` | `any(can_t)` | `all(can_f)` |
| **`K_OF_N(k; c_1..c_m)`** | `count(TRUE) >= k` | `count(TRUE) + count(UNKNOWN) < k` | `count(can_t) >= k` | `count(can_f) > m - k` |

### B. Consensus Boundary & Exact Canonical Equality
- **Storage Snapshotting**: All inputs (`circuit_id`, `atom_id`, `evidence_url`, `claim`, `claim_sha256`) are snapshotted into local variables prior to `gl.vm.run_nondet_unsafe(leader_fn, validator_fn)` (zero `self` references inside closures).
- **Fail-Closed Fetch Bounds**: Leader and validators independently fetch raw bytes via `gl.nondet.web.get(url)` enforcing HTTP `200` only, redirects disallowed (`301/302/307/308`), raw length within `[32, 16384]` bytes, and strict UTF-8 decoding. Any failure maps deterministically to `verdict = "UNCLEAR"`.
- **Prompt-Injection Firewall & Verbatim Grounding**: Raw text is isolated inside `<UNTRUSTED_EVIDENCE>` delimiters. The LLM classifies strictly into `{"HOLDS", "CONTRADICTED", "UNCLEAR"}`. Both `HOLDS` and `CONTRADICTED` require an exact verbatim substring quote (`12..240` chars) copied character-for-character from the fetched bytes; otherwise the verdict fails closed to `UNCLEAR`.
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

### C. Circuit Lifecycle States & Conservation of Funds
- `0` — `CIRCUIT_UNDECIDED`: open, evaluating active-frontier atoms.
- `1` — `CIRCUIT_DECIDED_TRUE`: terminal; `root == TRUE`, escrow credited to `withdrawable[beneficiary]`.
- `2` — `CIRCUIT_DECIDED_FALSE`: terminal; `root == FALSE`, escrow credited to `withdrawable[sponsor]`.
- `3` — `CIRCUIT_EXPIRED_REFUNDED`: terminal; permissionlessly expired past `deadline_ts`, escrow refunded to `withdrawable[sponsor]`.
- `4` — `CIRCUIT_CANCELLED`: terminal; cancelled by sponsor strictly before any atom evaluation (`atoms_evaluated_count == 0`).
- `5` — `CIRCUIT_UNSATISFIABLE`: terminal; `root` remains `UNKNOWN` but `can_be_true(root) == False`, pruning remaining atoms and refunding `withdrawable[sponsor]` immediately.

**Accounting Conservation Invariant** (asserted on every state-mutating call):
$$\text{total\_deposited\_wei} - \text{total\_withdrawn\_wei} = \text{total\_locked\_wei} + \text{total\_withdrawable\_wei}$$

---

## 3. Contract Interface

### Write Methods
- `create_circuit(circuit_id: str, beneficiary: str, duration_seconds: u256, circuit_spec_json: str)` *(payable)*: Escrows `gl.message.value`, validates circuit topology (3-color DFS acyclicity, exact DAG depth $\le 6$, full reachability, unique IDs, distinct gate children, unique `(evidence_url, claim)` pairs, 40-hex commit-SHA GitHub pinning), and persists the circuit.
- `evaluate_atom(circuit_id: str, atom_id: str)` *(permissionless)*: Verifies atom is on `active_frontier`, runs multi-validator consensus, recomputes Kleene values & possibility bounds bottom-up, prunes short-circuited subtrees, and immediately finalizes if `root` becomes `TRUE`, `FALSE`, or `UNSATISFIABLE`.
- `cancel_circuit(circuit_id: str)` *(sponsor-only, pre-evaluation)*: Refunds escrow to sponsor strictly before any atom evaluation begins (`atoms_evaluated_count == 0`).
- `expire_circuit(circuit_id: str)` *(permissionless)*: Finalizes an `UNDECIDED` circuit past `deadline_ts` and credits sponsor refund.
- `withdraw()`: Pull-payment native transfer (`emit_transfer`) of caller's balance using Checks-Effects-Interactions.

### View Methods
- `get_circuit(circuit_id: str)`: Returns full circuit metadata, status, `root_kleene_value`, `root_can_be_true`, per-gate states, per-atom envelopes, `active_frontier`, and `pruned_atoms`.
- `get_atom(circuit_id: str, atom_id: str)`: Returns full atom details and `is_in_active_frontier`.
- `get_accounting_state()`: Returns all 4 conservation counters, `circuit_count`, and `conservation_ok`.
- `get_withdrawable_balance(account: str)`: Returns withdrawable balance for an address.

---

## 4. Repository Structure

```text
Kleene-Gate/
├── contracts/
│   ├── kleene_gate.py                         # Main KleeneGate contract (45,417 B, LF, pinned runner)
│   └── probe_runner.py                        # Minimal pre-flight StudioNet runner probe
├── fixtures/
│   └── evidence/                              # Unstructured natural-language prose memos (zero JSON booleans)
│       ├── audit_report_v340.md               # 913 B — Mixed-signal prose audit memo (unit tests ok, 2 high findings -> FAILED)
│       ├── formal_verification_v340.md        # 340 B — Never evaluated (pruned by G_FAST=FALSE)
│       ├── review_alpha_v340.md               # 546 B — Reviewer Alpha prose approval memo
│       ├── review_beta_v340.md                # 556 B — Reviewer Beta prose approval memo
│       ├── review_gamma_v340.md               # 343 B — Never evaluated (pruned by 2-of-3=TRUE)
│       ├── security_bulletin_v340.md          # 729 B — False-alarm staging alert cleared in prose (no compromise on v3.4.0)
│       ├── security_bulletin_v341.md          # 594 B — Emergency prose advisory confirming v3.4.1 key compromise
│       └── runner_maintenance_note.md         # 758 B — Off-topic EU-West cache log + SYSTEM OVERRIDE prompt injection
├── scripts/
│   └── deploy_and_demo_studionet.py           # End-to-end StudioNet probe, deploy & 32-tx live demo runner
├── tests/
│   └── direct/
│       ├── conftest.py                        # Deterministic GenVM mock harness w/ adversarial leader hook
│       ├── test_circuit_validation.py         # Cycles, DAG depth, orphans, sybil pairs, URL pinning, bounds
│       ├── test_kleene_semantics_and_pruning.py # Truth tables, active-frontier pruning, possibility intervals, NOT(K_OF_N) soundness
│       └── test_adversarial_and_accounting.py # 9 leader-forgery attacks, 9 HTTP/byte failures, auth, 5-state conservation
├── gltest.config.yaml
├── pyproject.toml
├── requirements.txt
├── release_manifest.json                      # Machine-readable live StudioNet proof manifest (32/32 txs)
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
# 36 passed in 0.17s
```

---

## 6. Live Testnet Deployment & On-Chain Proof (GenLayer StudioNet)

- **Network**: GenLayer StudioNet (`Chain ID 61999`, RPC `https://studio.genlayer.com/api`)
- **Pre-Flight Probe Contract**: [`0x62da1E17b2e352860823a8fc58b2fb9D8D4d7E54`](https://explorer-studio.genlayer.com/address/0x62da1E17b2e352860823a8fc58b2fb9D8D4d7E54)
- **KleeneGate Contract Address**: [`0x971D12518fA6fC01D62D12c7a99ad4b748802aCf`](https://explorer-studio.genlayer.com/address/0x971D12518fA6fC01D62D12c7a99ad4b748802aCf)
- **Deployed Commit SHA**: [`52831faaaf7875638ce686f0e3caf23a64e72d06`](https://github.com/khezzed/Kleene-Gate/commit/52831faaaf7875638ce686f0e3caf23a64e72d06)
- **Pinned Contract Source**: [`contracts/kleene_gate.py`](https://github.com/khezzed/Kleene-Gate/blob/52831faaaf7875638ce686f0e3caf23a64e72d06/contracts/kleene_gate.py) (Git blob `3382d3b1761588df9b8891f62bb24b2a0493349a`, `45,417` bytes, LF)
- **Full Release Manifest**: [`release_manifest.json`](release_manifest.json)

### Complete Live StudioNet Transaction Log (32 / 32 Finalized)

All 22 state-mutating transactions record explicit on-chain `read_backs`; all 10 expected-failure guards record exact decoded rollback strings and `eq_outputs_count == 0`.

| Step | Action | Transaction Hash | Status | Leader Exec | Verified On-Chain Outcome |
| :---: | :--- | :--- | :---: | :---: | :--- |
| **P1** | Deploy `ProbeRunner` | [`0xd1e8...dde3`](https://explorer-studio.genlayer.com/transactions/0xd1e825607eb88973e0737e17d757eaf50eb2e1b4c59511aee8dc1f1a9c8bdde3) | `FINALIZED` | `SUCCESS` | Runner pre-flight contract deployed |
| **P2** | `ProbeRunner.ping` | [`0xcd91...ed9e`](https://explorer-studio.genlayer.com/transactions/0xcd91f3821eea6caddf8d89707ade14100e60df6da785ed9e901c62a910b0ed9e) | `FINALIZED` | `SUCCESS` | Read-back: `counter == 1, last_tag == "kleene-gate-v2-preflight"` |
| **D1** | Deploy `KleeneGate` | [`0xfee1...a2c6`](https://explorer-studio.genlayer.com/transactions/0xfee1f99d16deb3c5219e483d4060157fbcea818bce36f7172df33b7321c8a2c6) | `FINALIZED` | `SUCCESS` | Byte-identical LF deploy (`conservation_ok == True`) |
| **S1** | `create_circuit(REL-PASS)` | [`0xd5ab...e882`](https://explorer-studio.genlayer.com/transactions/0xd5ab993bff72c7d8890ea84a175d826bd3dbe890a372c99593b23060e102e882) | `FINALIZED` | `SUCCESS` | Escrowed `100` wei; 6 prose atoms, 5 nested gates (`AND`/`OR`/`NOT`/`2-of-3`) |
| **S2** | `evaluate_atom(REL-PASS, A_AUDIT)` | [`0x3062...5f92`](https://explorer-studio.genlayer.com/transactions/0x30625d537f55b6df78b0a4449c304cb102b09bc82b4f17e38e65d68edfcc5f92) | `FINALIZED` | `SUCCESS` | Mixed-signal prose `audit_report_v340.md` $\to$ `CONTRADICTED` $\implies$ `G_FAST=FALSE`, `A_FORMAL` pruned |
| **G1** | `evaluate_atom(REL-PASS, A_FORMAL)` | [`0xe010...28b1`](https://explorer-studio.genlayer.com/transactions/0xe010cea1b87659a8dc3d348247c7572626ff7b161b031754153d0b04762828b1) | `FINALIZED` | `ERROR` | `EXPECTED FAILURE`: `EXPECTED:ATOM_ALREADY_PRUNED` (`eq_outputs=0`) |
| **S3** | `evaluate_atom(REL-PASS, B_REV1)` | [`0x6370...2f63`](https://explorer-studio.genlayer.com/transactions/0x63704f6fc439014ccc659d754636cc113397edf2e7ddfdd340bd929e3f022f63) | `FINALIZED` | `SUCCESS` | Prose `review_alpha_v340.md` $\to$ `HOLDS` (`1/2` toward `2-of-3`) |
| **S4** | `evaluate_atom(REL-PASS, B_REV2)` | [`0x2d49...ae91`](https://explorer-studio.genlayer.com/transactions/0x2d491975a95dadcaeefd9a578e81c511de841124e41cde1cbc3ba126195eae91) | `FINALIZED` | `SUCCESS` | Prose `review_beta_v340.md` $\to$ `HOLDS` $\implies$ `G_QUORUM=TRUE`, `G_PATH=TRUE`, `B_REV3` pruned |
| **G2** | `evaluate_atom(REL-PASS, B_REV3)` | [`0xc795...0878`](https://explorer-studio.genlayer.com/transactions/0xc795298e46fd3f194765385dde621621d6010853e996e10207b2934821360878) | `FINALIZED` | `ERROR` | `EXPECTED FAILURE`: `EXPECTED:ATOM_ALREADY_PRUNED` (`eq_outputs=0`) |
| **G3** | Beneficiary `withdraw()` early | [`0x5ed1...9cda`](https://explorer-studio.genlayer.com/transactions/0x5ed1f5e23ccc96c57a3e9822805976132aea23078c9790b643e6724d4f2d9cda) | `FINALIZED` | `ERROR` | `EXPECTED FAILURE`: `EXPECTED:NOTHING_TO_WITHDRAW` (`NOT(V_EXPLOIT)` still `UNKNOWN`) |
| **G4** | Sponsor `cancel_circuit(REL-PASS)` | [`0x9f29...03ad`](https://explorer-studio.genlayer.com/transactions/0x9f298dd851325c84d69e3ef2fa049441777f2b4962b7f3fbd43aed1d2e2a03ad) | `FINALIZED` | `ERROR` | `EXPECTED FAILURE`: `EXPECTED:CIRCUIT_EVALUATION_STARTED` (anti-rugpull guard) |
| **S5** | `evaluate_atom(REL-PASS, V_EXPLOIT)` | [`0x3381...567e`](https://explorer-studio.genlayer.com/transactions/0x3381bb09948d14b0feb0f2569999668c621610e7f8c1b51734fe14b64c1b567e) | `FINALIZED` | `SUCCESS` | False-alarm prose `security_bulletin_v340.md` $\to$ `CONTRADICTED` $\implies$ `NOT=TRUE` $\implies$ `DECIDED_TRUE` (4 eval, 2 pruned) |
| **S6** | Beneficiary `withdraw()` | [`0xdf51...b273`](https://explorer-studio.genlayer.com/transactions/0xdf517dcfac12dd07a8a90ef50e62988d19cd93017215b9cb66a3065314e8b273) | `FINALIZED` | `SUCCESS` | Beneficiary withdrew `100` wei (`total_withdrawn_wei == 100`) |
| **S7** | `create_circuit(REL-VETO)` | [`0xc7bd...84cb`](https://explorer-studio.genlayer.com/transactions/0xc7bdc9f877118263c8fff641664237729fbb67bdd40f6aca71a3d86972fd84cb) | `FINALIZED` | `SUCCESS` | Escrowed `80` wei for early-veto test |
| **G5** | Stranger `cancel_circuit(REL-VETO)` | [`0x0d41...278d`](https://explorer-studio.genlayer.com/transactions/0x0d414ef477bb9e6f80a21e6996eb7d9bcec242598bec5b8e05281bc96d70278d) | `FINALIZED` | `ERROR` | `EXPECTED FAILURE`: `EXPECTED:UNAUTHORIZED_CALLER` |
| **S8** | `evaluate_atom(REL-VETO, V_EXPLOIT)` | [`0xf0cf...da53`](https://explorer-studio.genlayer.com/transactions/0xf0cf3c254ba642a35078f8d44841374ec611393609a5511864e74c2d5fbfda53) | `FINALIZED` | `SUCCESS` | Prose `security_bulletin_v341.md` $\to$ `HOLDS` $\implies$ `NOT=FALSE` $\implies$ `DECIDED_FALSE` in 1 tx (5 atoms pruned) |
| **G6** | `evaluate_atom(REL-VETO, B_REV1)` | [`0x7c3a...18cd`](https://explorer-studio.genlayer.com/transactions/0x7c3ab040935c82a76e4ad0856b1d6a2044fb4409f6bf25aaec7e8dd6137718cd) | `FINALIZED` | `ERROR` | `EXPECTED FAILURE`: `EXPECTED:CIRCUIT_ALREADY_FINAL` |
| **S9** | `create_circuit(REL-FAILCLOSED)` | [`0xddb3...0e64`](https://explorer-studio.genlayer.com/transactions/0xddb3ca19965290e80a80ec1652ecd0e33b40d6ce3f065db477b6305b73060e64) | `FINALIZED` | `SUCCESS` | Escrowed `60` wei (`duration = 150s`, `AND(B_REV1, NOT(V_EXPLOIT))`) |
| **S10** | `evaluate_atom(REL-FAILCLOSED, B_REV1)` | [`0xd319...7b41`](https://explorer-studio.genlayer.com/transactions/0xd319393cc320f46348d70901093adff3d77dac1d5234922fb6e5456438fb7b41) | `FINALIZED` | `SUCCESS` | Prose `review_alpha_v340.md` $\to$ `HOLDS` (`TRUE`) |
| **S11** | `evaluate_atom(REL-FAILCLOSED, V_EXPLOIT)` | [`0x7a4a...8580`](https://explorer-studio.genlayer.com/transactions/0x7a4af6f1f793864e355dfc033ddf61756b79a112849fcc0c9054cb187c848580) | `FINALIZED` | `SUCCESS` | Prompt-injected `runner_maintenance_note.md` $\to$ `UNCLEAR` $\implies$ `NOT(UNKNOWN)=UNKNOWN` (fail-closed) |
| **S12** | `create_circuit(REL-UNSAT)` | [`0x99d2...4444`](https://explorer-studio.genlayer.com/transactions/0x99d2861dbb1bc1787d201ff5e04146d127996f08c0a276759253b7b9d57af444) | `FINALIZED` | `SUCCESS` | Escrowed `50` wei (`K_OF_N(2; U_EXHAUST, F_FAIL, P_UNUSED)`) |
| **S13** | `evaluate_atom(REL-UNSAT, F_FAIL)` | [`0xf462...cc57`](https://explorer-studio.genlayer.com/transactions/0xf462de6aaee6f66076c6842a740bd1569cfdfca96be76ab7d38144ee3d48cc57) | `FINALIZED` | `SUCCESS` | Prose `audit_report_v340.md` $\to$ `CONTRADICTED` (`FALSE`) |
| **S14** | `evaluate_atom(REL-UNSAT, U_EXHAUST)` #1 | [`0xfd59...a99d`](https://explorer-studio.genlayer.com/transactions/0xfd59d915258a4618cb1c4e995cb3af3ee42f6f825cb098e1916dbeda5706a99d) | `FINALIZED` | `SUCCESS` | Attempt 1 `UNCLEAR` (still retriable; `root_can_be_true == True`) |
| **S15** | `evaluate_atom(REL-UNSAT, U_EXHAUST)` #2 | [`0x6735...eccd`](https://explorer-studio.genlayer.com/transactions/0x673509232b8902f5ff03904d6884caeeda3fa57d09ed18bf325d9197a816eccd) | `FINALIZED` | `SUCCESS` | Attempt 2 `UNCLEAR` exhausts atom $\implies$ `root_can_be_true == False` $\implies$ immediate `CIRCUIT_UNSATISFIABLE` (`P_UNUSED` pruned) |
| **G10** | `evaluate_atom(REL-UNSAT, P_UNUSED)` | [`0x489f...6850`](https://explorer-studio.genlayer.com/transactions/0x489f10f579104967e0234e22cc8b0b90c8b7e554a624d6d9cf671666cbe36850) | `FINALIZED` | `ERROR` | `EXPECTED FAILURE`: `EXPECTED:CIRCUIT_ALREADY_FINAL` (`eq_outputs=0`) |
| **S16** | `create_circuit(REL-CANCEL)` | [`0x52ed...2780`](https://explorer-studio.genlayer.com/transactions/0x52ed7ed4ceef475a5339a9a65506fc815b00794c2b1d900f0efc500e95432780) | `FINALIZED` | `SUCCESS` | Escrowed `40` wei for pre-evaluation cancel test |
| **S17** | `cancel_circuit(REL-CANCEL)` | [`0x08b8...e3dc`](https://explorer-studio.genlayer.com/transactions/0x08b8c463faa0eed69facd1c9c069c3855d0daf67024a805855bb4b388334e3dc) | `FINALIZED` | `SUCCESS` | Sponsor cancelled prior to evaluation $\implies$ `CIRCUIT_CANCELLED` (`40` wei credited) |
| **G7** | `create_circuit` w/ cycle `G1->G2->G1` | [`0xa255...be6b`](https://explorer-studio.genlayer.com/transactions/0xa255b88f3f8d42b16b5aee7f7d01c69beebba16357d4c8ce6dfdd0eb9a19be6b) | `FINALIZED` | `ERROR` | `EXPECTED FAILURE`: `EXPECTED:CIRCUIT_CYCLE_DETECTED` |
| **G8** | `create_circuit` w/ mutable `/main/` URL | [`0x4611...29a7`](https://explorer-studio.genlayer.com/transactions/0x4611d9b44cafa90552ba6b17d6f7c7670b7ad206d3f9ecff0873e9d3237a29a7) | `FINALIZED` | `ERROR` | `EXPECTED FAILURE`: `EXPECTED:UNPINNED_GITHUB_URL` |
| **G9** | Replay `evaluate_atom(REL-PASS, A_AUDIT)` | [`0xb531...5328`](https://explorer-studio.genlayer.com/transactions/0xb531d3ba84fd2f94d7dc0a3eb88162e7fd63cb6680a82ae1cac2b51ade475328) | `FINALIZED` | `ERROR` | `EXPECTED FAILURE`: `EXPECTED:CIRCUIT_ALREADY_FINAL` |
| **S18** | `expire_circuit(REL-FAILCLOSED)` | [`0x600c...24b2`](https://explorer-studio.genlayer.com/transactions/0x600c731447aadca46e86cdddd3237cb1f58fb300bc07dfc41f2274b436ab24b2) | `FINALIZED` | `SUCCESS` | Permissionless expiry past deadline $\implies$ `EXPIRED_REFUNDED` (`60` wei to Sponsor) |
| **S19** | Sponsor `withdraw()` | [`0xccfa...3542`](https://explorer-studio.genlayer.com/transactions/0xccfa7e56fac1aba1a67a312f0ee13ea87090f2ddf121a956cd89eac223753542) | `FINALIZED` | `SUCCESS` | Sponsor pulled `230` wei (`80+60+50+40`); final read-back `deposited=330, withdrawn=330, locked=0, withdrawable=0, conservation_ok=True` |
