import hashlib
import importlib.metadata
import json
import pathlib
import sys
import time
import urllib.request
from datetime import datetime, timezone

from genlayer_py import create_account, create_client
from genlayer_py.chains import studionet
from genlayer_py.types import TransactionHashVariant, TransactionStatus

ENDPOINT = "https://studio.genlayer.com/api"
EXPLORER_BASE = "https://explorer-studio.genlayer.com"
REPO_URL = "https://github.com/khezzed/Kleene-Gate"
DEPLOYED_COMMIT_SHA = "11ad896b4fbe929f9fbaf418e8e6ad22901c0eaf"

RAW_BASE = f"https://raw.githubusercontent.com/khezzed/Kleene-Gate/{DEPLOYED_COMMIT_SHA}/fixtures/evidence"

FIXTURE_FILES = [
    "audit_failed.json",
    "formal_spec_unused.json",
    "review_alpha_pass.json",
    "review_beta_pass.json",
    "review_gamma_unused.json",
    "security_clean.json",
    "security_compromise.json",
    "security_ambiguous_injection.json",
]

PINNED_FIXTURES = {name: f"{RAW_BASE}/{name}" for name in FIXTURE_FILES}
CTOR_ARGS = [["raw.githubusercontent.com"]]


def _log(msg: str) -> None:
    print(msg, flush=True)


def _install_resilient_rpc_retry(client) -> None:
    provider = getattr(client, "provider", None)
    if provider is None or getattr(provider, "_retry_installed", False):
        return
    orig_make_request = provider.make_request

    def make_request_with_retry(method, params):
        last_err = None
        for attempt in range(12):
            try:
                return orig_make_request(method, params)
            except Exception as err:
                last_err = err
                if attempt < 11:
                    wait_s = min(3.0 * (attempt + 1), 20.0)
                    _log(f"  [rpc-retry] {method} failed ({err}); retrying in {wait_s:.0f}s...")
                    time.sleep(wait_s)
                    continue
                raise
        raise last_err

    provider.make_request = make_request_with_retry
    provider._retry_installed = True


def _hex_hash(tx_hash) -> str:
    h = tx_hash.hex() if isinstance(tx_hash, (bytes, bytearray)) else str(tx_hash)
    return h if h.startswith("0x") else f"0x{h}"


def _extract_receipt_summary(tx_hash_hex: str, receipt: dict, expected_failure: bool, label: str) -> dict:
    status_name = str(receipt.get("status_name", receipt.get("status", "")))
    consensus_data = receipt.get("consensus_data") or {}
    leader_receipts = consensus_data.get("leader_receipt") or []
    leader_exec = "UNKNOWN"
    leader_error = None
    if len(leader_receipts) > 0 and isinstance(leader_receipts[0], dict):
        leader_exec = str(leader_receipts[0].get("execution_result", "UNKNOWN"))
        res_obj = leader_receipts[0].get("result")
        res_payload = res_obj.get("payload") if isinstance(res_obj, dict) else None
        genvm_res = leader_receipts[0].get("genvm_result") or {}
        leader_error = res_payload or genvm_res.get("stderr") or leader_receipts[0].get("error")
    votes = consensus_data.get("votes") or {}
    return {
        "label": label,
        "tx_hash": tx_hash_hex,
        "explorer_url": f"{EXPLORER_BASE}/transactions/{tx_hash_hex}",
        "expected_failure": expected_failure,
        "status_name": status_name,
        "leader_execution_result": leader_exec,
        "leader_error": leader_error,
        "votes": votes,
    }


def _send_with_retry(fn, max_attempts: int = 5):
    last_err = None
    for attempt in range(max_attempts):
        try:
            return fn()
        except Exception as err:
            last_err = err
            if attempt < max_attempts - 1:
                wait_s = (attempt + 1) * 4
                _log(f"  [retry] transient call error ({err}); retrying in {wait_s}s...")
                time.sleep(wait_s)
                continue
            raise last_err


def _verify_pinned_fixtures() -> list[dict]:
    _log("=== Step 0: Verifying raw GitHub fixture reachability & byte sizes ===")
    verified = []
    for fname, url in PINNED_FIXTURES.items():
        local_bytes = (pathlib.Path("fixtures/evidence") / fname).read_bytes()
        req = urllib.request.Request(url, headers={"User-Agent": "kleene-gate-verifier"})
        with urllib.request.urlopen(req, timeout=20) as resp:
            status = int(resp.status)
            remote_bytes = resp.read()
        if status != 200:
            raise RuntimeError(f"Fixture {url} returned HTTP {status}")
        if remote_bytes != local_bytes:
            raise RuntimeError(f"Fixture {fname} remote bytes differ from local file")
        if not (32 <= len(remote_bytes) <= 16384):
            raise RuntimeError(f"Fixture {fname} size {len(remote_bytes)} outside [32, 16384]")
        sha = hashlib.sha256(remote_bytes).hexdigest()
        _log(f"  OK {status} | {len(remote_bytes):4d} bytes | sha256={sha[:12]} | {fname}")
        verified.append({
            "file": fname,
            "url": url,
            "http_status": status,
            "raw_bytes": len(remote_bytes),
            "sha256": sha,
        })
    return verified


def _showcase_spec(veto_fixture: str, release_ver: str) -> str:
    return json.dumps({
        "root_gate_id": "G_ROOT",
        "atoms": [
            {
                "id": "A_AUDIT",
                "evidence_url": PINNED_FIXTURES["audit_failed.json"],
                "claim": "The security audit report for release v3.4.0 states that the audit PASSED with zero unresolved high-severity findings.",
            },
            {
                "id": "A_FORMAL",
                "evidence_url": PINNED_FIXTURES["formal_spec_unused.json"],
                "claim": "Formal verification for release v3.4.0 PASSED all safety invariants.",
            },
            {
                "id": "B_REV1",
                "evidence_url": PINNED_FIXTURES["review_alpha_pass.json"],
                "claim": "Independent reviewer Alpha formally APPROVED release v3.4.0 after verifying all regression tests passed.",
            },
            {
                "id": "B_REV2",
                "evidence_url": PINNED_FIXTURES["review_beta_pass.json"],
                "claim": "Independent reviewer Beta formally APPROVED release v3.4.0 after verifying access-control and accounting invariants.",
            },
            {
                "id": "B_REV3",
                "evidence_url": PINNED_FIXTURES["review_gamma_unused.json"],
                "claim": "Independent reviewer Gamma formally APPROVED release v3.4.0.",
            },
            {
                "id": "V_EXPLOIT",
                "evidence_url": PINNED_FIXTURES[veto_fixture],
                "claim": f"The security bulletin confirms an active signing-key compromise or confirmed critical exploit affecting release {release_ver}.",
            },
        ],
        "gates": [
            {"id": "G_FAST", "op": "AND", "children": ["A_AUDIT", "A_FORMAL"]},
            {"id": "G_QUORUM", "op": "K_OF_N", "k": 2, "children": ["B_REV1", "B_REV2", "B_REV3"]},
            {"id": "G_PATH", "op": "OR", "children": ["G_FAST", "G_QUORUM"]},
            {"id": "G_NO_VETO", "op": "NOT", "children": ["V_EXPLOIT"]},
            {"id": "G_ROOT", "op": "AND", "children": ["G_PATH", "G_NO_VETO"]},
        ],
    })


def _fail_closed_spec() -> str:
    return json.dumps({
        "root_gate_id": "G_ROOT",
        "atoms": [
            {
                "id": "B_REV1",
                "evidence_url": PINNED_FIXTURES["review_alpha_pass.json"],
                "claim": "Independent reviewer Alpha formally APPROVED release v3.4.0 after verifying all regression tests passed.",
            },
            {
                "id": "V_EXPLOIT",
                "evidence_url": PINNED_FIXTURES["security_ambiguous_injection.json"],
                "claim": "The security bulletin confirms an active signing-key compromise or confirmed critical exploit affecting release v3.4.2.",
            },
        ],
        "gates": [
            {"id": "G_NO_VETO", "op": "NOT", "children": ["V_EXPLOIT"]},
            {"id": "G_ROOT", "op": "AND", "children": ["B_REV1", "G_NO_VETO"]},
        ],
    })


def _write_lf_json(path: pathlib.Path, data: dict) -> None:
    raw = (json.dumps(data, indent=2) + "\n").replace("\r\n", "\n").encode("utf-8")
    path.write_bytes(raw)


def main() -> None:
    fixture_records = _verify_pinned_fixtures()

    contract_path = pathlib.Path("contracts/kleene_gate.py")
    probe_path = pathlib.Path("contracts/probe_runner.py")
    raw_bytes = contract_path.read_bytes()
    probe_bytes = probe_path.read_bytes()
    if b"\r\n" in raw_bytes or b"\r\n" in probe_bytes:
        raise RuntimeError("CRLF detected in contract source; LF required")

    blob_sha1 = hashlib.sha1(f"blob {len(raw_bytes)}\0".encode("utf-8") + raw_bytes).hexdigest()
    probe_blob_sha1 = hashlib.sha1(f"blob {len(probe_bytes)}\0".encode("utf-8") + probe_bytes).hexdigest()
    code_str = raw_bytes.decode("utf-8")
    probe_str = probe_bytes.decode("utf-8")
    runner_header = code_str.splitlines()[0].strip()

    sponsor_acct = create_account()
    beneficiary_acct = create_account()
    stranger_acct = create_account()

    client = create_client(chain=studionet, endpoint=ENDPOINT, account=sponsor_acct)
    _install_resilient_rpc_retry(client)

    _log("=== Step 1: Funding sponsor, beneficiary, and stranger accounts on StudioNet ===")
    for acct in (sponsor_acct, beneficiary_acct, stranger_acct):
        _send_with_retry(lambda a=acct: client.fund_account(address=a.address, amount=10**21))
    time.sleep(2)

    tx_log: list[dict] = []

    def send_and_wait(*, label: str, send_fn, expected_failure: bool = False, accept_retries: int = 80) -> tuple[dict, dict]:
        tx_hash = _send_with_retry(send_fn)
        tx_hex = _hex_hash(tx_hash)
        _log(f"[{label}] tx={tx_hex} -> waiting for ACCEPTED + FINALIZED...")

        def _wait(status_enum, retries_n):
            for attempt in range(5):
                try:
                    return client.wait_for_transaction_receipt(
                        transaction_hash=tx_hex,
                        status=status_enum,
                        interval=3000,
                        retries=retries_n,
                    )
                except Exception as err:
                    if attempt < 4:
                        _log(f"  [wait-retry] {status_enum} ({err}); retrying in 4s...")
                        time.sleep(4)
                        continue
                    raise

        acc_rcpt = _wait(TransactionStatus.ACCEPTED, accept_retries)
        acc_status = str(acc_rcpt.get("status_name", acc_rcpt.get("status", "")))
        fin_rcpt = _wait(TransactionStatus.FINALIZED, 80)
        summary = _extract_receipt_summary(tx_hex, fin_rcpt, expected_failure, label)
        summary["accepted_status_observed"] = acc_status
        _log(
            f"  -> status={summary['status_name']}, leader_exec={summary['leader_execution_result']}, "
            f"expected_failure={expected_failure}"
        )
        if summary["status_name"] != "FINALIZED":
            raise RuntimeError(f"Tx {tx_hex} did not finalize: {summary}")
        if not expected_failure and summary["leader_execution_result"] != "SUCCESS":
            raise RuntimeError(f"Unexpected ERROR on {label} ({tx_hex}): {summary}")
        if expected_failure and summary["leader_execution_result"] != "ERROR":
            raise RuntimeError(f"Expected ERROR guard did not trigger on {label} ({tx_hex}): {summary}")
        tx_log.append(summary)
        return summary, fin_rcpt

    def read_at(addr: str, fn_name: str, args: list | None = None):
        return _send_with_retry(
            lambda: client.read_contract(
                address=addr,
                function_name=fn_name,
                args=args or [],
                account=sponsor_acct,
                transaction_hash_variant=TransactionHashVariant.LATEST_NONFINAL,
            )
        )

    # =========================================================================
    # Pre-Flight Runner Probe (Guide Section 5)
    # =========================================================================
    _log("=== Step 2: Pre-Flight Runner Probe ===")
    p_deploy_sum, p_deploy_rcpt = send_and_wait(
        label="P1: deploy_probe_runner",
        send_fn=lambda: client.deploy_contract(code=probe_str, account=sponsor_acct, args=["init"]),
    )
    probe_address = p_deploy_rcpt.get("recipient") or p_deploy_rcpt.get("data", {}).get("contract_address")
    if not probe_address:
        raise RuntimeError(f"Missing probe contract address: {p_deploy_rcpt}")
    _log(f"  ProbeRunner address: {probe_address}")

    send_and_wait(
        label="P2: probe_ping",
        send_fn=lambda: client.write_contract(
            address=probe_address,
            function_name="ping",
            account=sponsor_acct,
            args=["kleene-gate-preflight"],
        ),
    )
    probe_state = read_at(probe_address, "status")
    tx_log[-1]["read_backs"] = {"probe.status": probe_state}
    assert probe_state["counter"] == 1 and probe_state["last_tag"] == "kleene-gate-preflight", probe_state
    _log(f"  Probe verified: {probe_state}")

    # =========================================================================
    # Main Contract Deployment
    # =========================================================================
    _log("=== Step 3: Deploying KleeneGate ===")
    d_sum, d_rcpt = send_and_wait(
        label="D1: deploy_kleene_gate",
        send_fn=lambda: client.deploy_contract(code=code_str, account=sponsor_acct, args=CTOR_ARGS),
    )
    contract_address = d_rcpt.get("recipient") or d_rcpt.get("data", {}).get("contract_address")
    if not contract_address:
        raise RuntimeError(f"Missing KleeneGate contract address: {d_rcpt}")
    _log(f"  KleeneGate address: {contract_address}")

    acct0 = read_at(contract_address, "get_accounting_state")
    d_sum["read_backs"] = {"get_accounting_state": acct0}
    assert acct0["conservation_ok"] is True and acct0["circuit_count"] == 0

    # =========================================================================
    # Circuit 1: REL-PASS (Nested AND/OR/NOT/2-of-3 + Active-Frontier Pruning)
    # =========================================================================
    _log("=== Step 4: Circuit 1 (REL-PASS) — Short-Circuit Pruning & Settlement ===")
    send_and_wait(
        label="S1: create_circuit (REL-PASS, 100 wei, nested AND/OR/NOT/2-of-3)",
        send_fn=lambda: client.write_contract(
            address=contract_address,
            function_name="create_circuit",
            account=sponsor_acct,
            value=100,
            args=["REL-PASS", beneficiary_acct.address, 1800, _showcase_spec("security_clean.json", "v3.4.0")],
        ),
    )
    tx_log[-1]["read_backs"] = {"get_circuit(REL-PASS)": read_at(contract_address, "get_circuit", ["REL-PASS"])}

    # S2: A_AUDIT -> CONTRADICTED -> G_FAST=FALSE -> A_FORMAL pruned
    send_and_wait(
        label="S2: evaluate_atom (REL-PASS, A_AUDIT -> CONTRADICTED, prunes A_FORMAL)",
        send_fn=lambda: client.write_contract(
            address=contract_address,
            function_name="evaluate_atom",
            account=stranger_acct,
            args=["REL-PASS", "A_AUDIT"],
        ),
    )
    c1_s2 = read_at(contract_address, "get_circuit", ["REL-PASS"])
    tx_log[-1]["read_backs"] = {"get_circuit(REL-PASS)": c1_s2}
    if c1_s2["atoms"]["A_AUDIT"]["verdict"] != "CONTRADICTED":
        raise RuntimeError(f"STOPPING: Unexpected A_AUDIT verdict: {c1_s2['atoms']['A_AUDIT']}")
    assert c1_s2["gates"]["G_FAST"]["kleene_value"] == 2
    assert "A_FORMAL" in c1_s2["pruned_atoms"]

    # G1: Evaluating pruned A_FORMAL MUST revert
    send_and_wait(
        label="G1: guard_pruned_atom (REL-PASS, A_FORMAL -> EXPECTED:ATOM_ALREADY_PRUNED)",
        send_fn=lambda: client.write_contract(
            address=contract_address,
            function_name="evaluate_atom",
            account=stranger_acct,
            args=["REL-PASS", "A_FORMAL"],
        ),
        expected_failure=True,
    )

    # S3: B_REV1 -> HOLDS
    send_and_wait(
        label="S3: evaluate_atom (REL-PASS, B_REV1 -> HOLDS)",
        send_fn=lambda: client.write_contract(
            address=contract_address,
            function_name="evaluate_atom",
            account=stranger_acct,
            args=["REL-PASS", "B_REV1"],
        ),
    )
    c1_s3 = read_at(contract_address, "get_circuit", ["REL-PASS"])
    tx_log[-1]["read_backs"] = {"get_circuit(REL-PASS)": c1_s3}
    if c1_s3["atoms"]["B_REV1"]["verdict"] != "HOLDS":
        raise RuntimeError(f"STOPPING: Unexpected B_REV1 verdict: {c1_s3['atoms']['B_REV1']}")

    # S4: B_REV2 -> HOLDS -> G_QUORUM(2-of-3)=TRUE -> G_PATH=TRUE -> B_REV3 pruned
    send_and_wait(
        label="S4: evaluate_atom (REL-PASS, B_REV2 -> HOLDS, 2-of-3 quorum prunes B_REV3)",
        send_fn=lambda: client.write_contract(
            address=contract_address,
            function_name="evaluate_atom",
            account=stranger_acct,
            args=["REL-PASS", "B_REV2"],
        ),
    )
    c1_s4 = read_at(contract_address, "get_circuit", ["REL-PASS"])
    tx_log[-1]["read_backs"] = {"get_circuit(REL-PASS)": c1_s4}
    if c1_s4["atoms"]["B_REV2"]["verdict"] != "HOLDS":
        raise RuntimeError(f"STOPPING: Unexpected B_REV2 verdict: {c1_s4['atoms']['B_REV2']}")
    assert c1_s4["gates"]["G_QUORUM"]["kleene_value"] == 1
    assert c1_s4["gates"]["G_PATH"]["kleene_value"] == 1
    assert c1_s4["active_frontier"] == ["V_EXPLOIT"]
    assert "B_REV3" in c1_s4["pruned_atoms"]

    # G2: Evaluating pruned B_REV3 MUST revert
    send_and_wait(
        label="G2: guard_pruned_quorum_atom (REL-PASS, B_REV3 -> EXPECTED:ATOM_ALREADY_PRUNED)",
        send_fn=lambda: client.write_contract(
            address=contract_address,
            function_name="evaluate_atom",
            account=stranger_acct,
            args=["REL-PASS", "B_REV3"],
        ),
        expected_failure=True,
    )

    # G3: Beneficiary cannot withdraw while NOT(V_EXPLOIT) is UNKNOWN
    send_and_wait(
        label="G3: guard_premature_withdraw (Beneficiary before V_EXPLOIT -> EXPECTED:NOTHING_TO_WITHDRAW)",
        send_fn=lambda: client.write_contract(
            address=contract_address,
            function_name="withdraw",
            account=beneficiary_acct,
            args=[],
        ),
        expected_failure=True,
    )

    # G4: Sponsor cannot rugpull/cancel after evaluation started
    send_and_wait(
        label="G4: guard_mid_eval_cancel (Sponsor -> EXPECTED:CIRCUIT_EVALUATION_STARTED)",
        send_fn=lambda: client.write_contract(
            address=contract_address,
            function_name="cancel_circuit",
            account=sponsor_acct,
            args=["REL-PASS"],
        ),
        expected_failure=True,
    )

    # S5: V_EXPLOIT -> CONTRADICTED -> NOT(FALSE)=TRUE -> ROOT=TRUE -> DECIDED_TRUE
    send_and_wait(
        label="S5: evaluate_atom (REL-PASS, V_EXPLOIT -> CONTRADICTED => NOT=TRUE => DECIDED_TRUE)",
        send_fn=lambda: client.write_contract(
            address=contract_address,
            function_name="evaluate_atom",
            account=stranger_acct,
            args=["REL-PASS", "V_EXPLOIT"],
        ),
    )
    c1_s5 = read_at(contract_address, "get_circuit", ["REL-PASS"])
    tx_log[-1]["read_backs"] = {
        "get_circuit(REL-PASS)": c1_s5,
        "beneficiary_withdrawable": read_at(contract_address, "get_withdrawable_balance", [beneficiary_acct.address]),
    }
    if c1_s5["atoms"]["V_EXPLOIT"]["verdict"] != "CONTRADICTED":
        raise RuntimeError(f"STOPPING: Unexpected V_EXPLOIT verdict in REL-PASS: {c1_s5['atoms']['V_EXPLOIT']}")
    assert c1_s5["status"] == 1 and c1_s5["root_kleene_value"] == 1
    assert c1_s5["atoms_evaluated_count"] == 4 and c1_s5["atoms_pruned_count"] == 2

    # S6: Beneficiary withdraws 100 wei
    send_and_wait(
        label="S6: withdraw (Beneficiary pulls 100 wei)",
        send_fn=lambda: client.write_contract(
            address=contract_address,
            function_name="withdraw",
            account=beneficiary_acct,
            args=[],
        ),
    )
    tx_log[-1]["read_backs"] = {"get_accounting_state": read_at(contract_address, "get_accounting_state")}

    # =========================================================================
    # Circuit 2: REL-VETO (Early Veto Kill via NOT(TRUE) = FALSE)
    # =========================================================================
    _log("=== Step 5: Circuit 2 (REL-VETO) — Early Kill via NOT(V_EXPLOIT) ===")
    send_and_wait(
        label="S7: create_circuit (REL-VETO, 80 wei)",
        send_fn=lambda: client.write_contract(
            address=contract_address,
            function_name="create_circuit",
            account=sponsor_acct,
            value=80,
            args=["REL-VETO", beneficiary_acct.address, 1800, _showcase_spec("security_compromise.json", "v3.4.1")],
        ),
    )

    # G5: Unauthorized stranger cannot cancel circuit
    send_and_wait(
        label="G5: guard_unauthorized_cancel (Stranger -> EXPECTED:UNAUTHORIZED_CALLER)",
        send_fn=lambda: client.write_contract(
            address=contract_address,
            function_name="cancel_circuit",
            account=stranger_acct,
            args=["REL-VETO"],
        ),
        expected_failure=True,
    )

    # S8: V_EXPLOIT -> HOLDS -> NOT(TRUE)=FALSE -> ROOT=FALSE immediately (5 positive atoms skipped!)
    send_and_wait(
        label="S8: evaluate_atom (REL-VETO, V_EXPLOIT -> HOLDS => NOT=FALSE => DECIDED_FALSE)",
        send_fn=lambda: client.write_contract(
            address=contract_address,
            function_name="evaluate_atom",
            account=stranger_acct,
            args=["REL-VETO", "V_EXPLOIT"],
        ),
    )
    c2_s8 = read_at(contract_address, "get_circuit", ["REL-VETO"])
    tx_log[-1]["read_backs"] = {"get_circuit(REL-VETO)": c2_s8}
    if c2_s8["atoms"]["V_EXPLOIT"]["verdict"] != "HOLDS":
        raise RuntimeError(f"STOPPING: Unexpected V_EXPLOIT verdict in REL-VETO: {c2_s8['atoms']['V_EXPLOIT']}")
    assert c2_s8["status"] == 2 and c2_s8["root_kleene_value"] == 2 and c2_s8["atoms_pruned_count"] == 5

    # G6: Evaluating positive atom after early veto kill MUST revert
    send_and_wait(
        label="G6: guard_eval_after_veto (REL-VETO, B_REV1 -> EXPECTED:CIRCUIT_ALREADY_FINAL)",
        send_fn=lambda: client.write_contract(
            address=contract_address,
            function_name="evaluate_atom",
            account=stranger_acct,
            args=["REL-VETO", "B_REV1"],
        ),
        expected_failure=True,
    )

    # =========================================================================
    # Circuit 3: REL-FAILCLOSED (NOT(UNKNOWN)==UNKNOWN + Prompt Injection + Expiry)
    # =========================================================================
    _log("=== Step 6: Circuit 3 (REL-FAILCLOSED) — Fail-Closed NOT(UNKNOWN) & Expiry ===")
    send_and_wait(
        label="S9: create_circuit (REL-FAILCLOSED, 60 wei, duration=150s)",
        send_fn=lambda: client.write_contract(
            address=contract_address,
            function_name="create_circuit",
            account=sponsor_acct,
            value=60,
            args=["REL-FAILCLOSED", beneficiary_acct.address, 150, _fail_closed_spec()],
        ),
    )
    c3_init = read_at(contract_address, "get_circuit", ["REL-FAILCLOSED"])
    c3_deadline = int(c3_init["deadline_ts"])
    tx_log[-1]["read_backs"] = {"get_circuit(REL-FAILCLOSED)": c3_init}

    # S10: B_REV1 -> HOLDS
    send_and_wait(
        label="S10: evaluate_atom (REL-FAILCLOSED, B_REV1 -> HOLDS)",
        send_fn=lambda: client.write_contract(
            address=contract_address,
            function_name="evaluate_atom",
            account=stranger_acct,
            args=["REL-FAILCLOSED", "B_REV1"],
        ),
    )

    # S11: V_EXPLOIT against prompt-injected off-topic log -> UNCLEAR => NOT(UNKNOWN)==UNKNOWN
    send_and_wait(
        label="S11: evaluate_atom (REL-FAILCLOSED, V_EXPLOIT -> UNCLEAR => fail-closed NOT(UNKNOWN)=UNKNOWN)",
        send_fn=lambda: client.write_contract(
            address=contract_address,
            function_name="evaluate_atom",
            account=stranger_acct,
            args=["REL-FAILCLOSED", "V_EXPLOIT"],
        ),
    )
    c3_s11 = read_at(contract_address, "get_circuit", ["REL-FAILCLOSED"])
    tx_log[-1]["read_backs"] = {"get_circuit(REL-FAILCLOSED)": c3_s11}
    if c3_s11["atoms"]["V_EXPLOIT"]["verdict"] != "UNCLEAR":
        raise RuntimeError(f"STOPPING: Prompt-injected atom did NOT fail closed to UNCLEAR: {c3_s11['atoms']['V_EXPLOIT']}")
    assert c3_s11["gates"]["G_NO_VETO"]["kleene_value"] == 0
    assert c3_s11["root_kleene_value"] == 0 and c3_s11["status"] == 0

    # =========================================================================
    # Additional Structural, Pinning & Replay Guards (while C3 deadline ticks)
    # =========================================================================
    _log("=== Step 7: Structural Cycle, Unpinned URL, and Replay Guards ===")
    cyclic_spec = json.dumps({
        "root_gate_id": "G1",
        "atoms": [
            {"id": "A1", "evidence_url": PINNED_FIXTURES["review_alpha_pass.json"], "claim": "Alpha approved release v3.4.0."},
            {"id": "A2", "evidence_url": PINNED_FIXTURES["review_beta_pass.json"], "claim": "Beta approved release v3.4.0."},
        ],
        "gates": [
            {"id": "G1", "op": "AND", "children": ["A1", "G2"]},
            {"id": "G2", "op": "OR", "children": ["A2", "G1"]},
        ],
    })
    send_and_wait(
        label="G7: guard_cyclic_circuit (G1->G2->G1 -> EXPECTED:CIRCUIT_CYCLE_DETECTED)",
        send_fn=lambda: client.write_contract(
            address=contract_address,
            function_name="create_circuit",
            account=sponsor_acct,
            value=10,
            args=["BAD-CYCLE", beneficiary_acct.address, 300, cyclic_spec],
        ),
        expected_failure=True,
    )

    unpinned_spec = json.dumps({
        "root_gate_id": "G1",
        "atoms": [
            {
                "id": "A1",
                "evidence_url": "https://raw.githubusercontent.com/khezzed/Kleene-Gate/main/fixtures/evidence/review_alpha_pass.json",
                "claim": "Alpha approved release v3.4.0.",
            },
            {"id": "A2", "evidence_url": PINNED_FIXTURES["review_beta_pass.json"], "claim": "Beta approved release v3.4.0."},
        ],
        "gates": [{"id": "G1", "op": "AND", "children": ["A1", "A2"]}],
    })
    send_and_wait(
        label="G8: guard_unpinned_branch_url (/main/ -> EXPECTED:UNPINNED_GITHUB_URL)",
        send_fn=lambda: client.write_contract(
            address=contract_address,
            function_name="create_circuit",
            account=sponsor_acct,
            value=10,
            args=["BAD-URL", beneficiary_acct.address, 300, unpinned_spec],
        ),
        expected_failure=True,
    )

    send_and_wait(
        label="G9: guard_replay_finalized_circuit (REL-PASS, A_AUDIT -> EXPECTED:CIRCUIT_ALREADY_FINAL)",
        send_fn=lambda: client.write_contract(
            address=contract_address,
            function_name="evaluate_atom",
            account=stranger_acct,
            args=["REL-PASS", "A_AUDIT"],
        ),
        expected_failure=True,
    )

    # =========================================================================
    # Deadline Expiry & Final Sponsor Withdrawal
    # =========================================================================
    now_utc = int(time.time())
    if now_utc <= c3_deadline + 6:
        sleep_s = (c3_deadline + 8) - now_utc
        _log(f"Waiting {sleep_s}s for REL-FAILCLOSED deadline ({c3_deadline}) to pass...")
        time.sleep(sleep_s)

    send_and_wait(
        label="S12: expire_circuit (REL-FAILCLOSED -> permissionless fail-closed refund)",
        send_fn=lambda: client.write_contract(
            address=contract_address,
            function_name="expire_circuit",
            account=stranger_acct,
            args=["REL-FAILCLOSED"],
        ),
    )
    c3_final = read_at(contract_address, "get_circuit", ["REL-FAILCLOSED"])
    tx_log[-1]["read_backs"] = {"get_circuit(REL-FAILCLOSED)": c3_final}
    assert c3_final["status"] == 3

    send_and_wait(
        label="S13: withdraw (Sponsor pulls 80 + 60 = 140 wei refunds)",
        send_fn=lambda: client.write_contract(
            address=contract_address,
            function_name="withdraw",
            account=sponsor_acct,
            args=[],
        ),
    )
    acct_final = read_at(contract_address, "get_accounting_state")
    tx_log[-1]["read_backs"] = {"get_accounting_state": acct_final}
    assert acct_final["conservation_ok"] is True
    assert acct_final["total_deposited_wei"] == 240
    assert acct_final["total_locked_wei"] == 0
    assert acct_final["total_withdrawable_wei"] == 0
    assert acct_final["total_withdrawn_wei"] == 240

    manifest = {
        "project": "KleeneGate — 3-Valued Kleene Predicate Circuit with Active-Frontier Short-Circuit Pruning",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "network": {
            "name": "studionet",
            "chain_id": 61999,
            "rpc_endpoint": ENDPOINT,
            "explorer_base_url": EXPLORER_BASE,
        },
        "source_verification": {
            "repository_url": REPO_URL,
            "contract_path": "contracts/kleene_gate.py",
            "probe_contract_path": "contracts/probe_runner.py",
            "deployed_commit_sha": DEPLOYED_COMMIT_SHA,
            "git_blob_sha1": blob_sha1,
            "probe_git_blob_sha1": probe_blob_sha1,
            "byte_length": len(raw_bytes),
            "line_endings": "LF",
            "runner_header": runner_header,
        },
        "toolchain": {
            "python_version": sys.version.split()[0],
            "genlayer_py": importlib.metadata.version("genlayer-py"),
            "genvm_linter": importlib.metadata.version("genvm-linter"),
            "genlayer_test": importlib.metadata.version("genlayer-test"),
        },
        "evidence_fixtures": fixture_records,
        "deployment": {
            "probe_contract_address": probe_address,
            "probe_explorer_url": f"{EXPLORER_BASE}/address/{probe_address}",
            "contract_address": contract_address,
            "explorer_contract_url": f"{EXPLORER_BASE}/address/{contract_address}",
            "sponsor_address": sponsor_acct.address,
            "beneficiary_address": beneficiary_acct.address,
            "stranger_address": stranger_acct.address,
            "constructor_args": CTOR_ARGS,
        },
        "transactions": tx_log,
    }

    manifest_path = pathlib.Path("release_manifest.json")
    _write_lf_json(manifest_path, manifest)
    _log(f"\nSUCCESS! All {len(tx_log)} transactions finalized. Wrote {manifest_path.resolve()}")


if __name__ == "__main__":
    main()
