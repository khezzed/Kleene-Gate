import json
import pathlib
import pytest
from conftest import MockWebResponse, UserError, u256
from kleene_gate import (
    CIRCUIT_DECIDED_FALSE,
    CIRCUIT_DECIDED_TRUE,
    CIRCUIT_EXPIRED_REFUNDED,
    CIRCUIT_UNDECIDED,
    KLEENE_FALSE,
    KLEENE_TRUE,
    KLEENE_UNKNOWN,
    KleeneGate,
    _evaluate_gate_kleene_fn,
)

SPONSOR = "0x1111111111111111111111111111111111111111"
BENEFICIARY = "0x2222222222222222222222222222222222222222"
EVALUATOR = "0x3333333333333333333333333333333333333333"
PINNED_SHA = "b" * 40
FIXTURES_DIR = pathlib.Path(__file__).resolve().parents[2] / "fixtures" / "evidence"


def _url(fname: str) -> str:
    return f"https://raw.githubusercontent.com/khezzed/Kleene-Gate/{PINNED_SHA}/fixtures/evidence/{fname}"


def _mount_all_fixtures(env) -> None:
    for p in FIXTURES_DIR.glob("*.json"):
        env.web_responses[_url(p.name)] = MockWebResponse(status=200, body=p.read_bytes())


def _showcase_circuit_spec(veto_fixture: str, release_ver: str) -> dict:
    """
    ROOT = AND( G_PATH, G_NO_VETO )
      G_PATH    = OR( G_FAST, G_QUORUM )
        G_FAST   = AND( A_AUDIT, A_FORMAL )
        G_QUORUM = K_OF_N(2; B_REV1, B_REV2, B_REV3)
      G_NO_VETO = NOT( V_EXPLOIT )
    """
    return {
        "root_gate_id": "G_ROOT",
        "atoms": [
            {
                "id": "A_AUDIT",
                "evidence_url": _url("audit_failed.json"),
                "claim": "The security audit report for release v3.4.0 states that the audit PASSED with zero unresolved high-severity findings.",
            },
            {
                "id": "A_FORMAL",
                "evidence_url": _url("formal_spec_unused.json"),
                "claim": "Formal verification for release v3.4.0 PASSED all safety invariants.",
            },
            {
                "id": "B_REV1",
                "evidence_url": _url("review_alpha_pass.json"),
                "claim": "Independent reviewer Alpha formally APPROVED release v3.4.0 after verifying all regression tests passed.",
            },
            {
                "id": "B_REV2",
                "evidence_url": _url("review_beta_pass.json"),
                "claim": "Independent reviewer Beta formally APPROVED release v3.4.0 after verifying access-control and accounting invariants.",
            },
            {
                "id": "B_REV3",
                "evidence_url": _url("review_gamma_unused.json"),
                "claim": "Independent reviewer Gamma formally APPROVED release v3.4.0.",
            },
            {
                "id": "V_EXPLOIT",
                "evidence_url": _url(veto_fixture),
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
    }


def test_exact_kleene_three_valued_truth_tables():
    U, T, F = int(KLEENE_UNKNOWN), int(KLEENE_TRUE), int(KLEENE_FALSE)

    # NOT: fail-closed on UNKNOWN
    assert _evaluate_gate_kleene_fn("NOT", 0, [T]) == F
    assert _evaluate_gate_kleene_fn("NOT", 0, [F]) == T
    assert _evaluate_gate_kleene_fn("NOT", 0, [U]) == U

    # AND: FALSE dominates UNKNOWN
    assert _evaluate_gate_kleene_fn("AND", 0, [F, U]) == F
    assert _evaluate_gate_kleene_fn("AND", 0, [T, U]) == U
    assert _evaluate_gate_kleene_fn("AND", 0, [T, T]) == T

    # OR: TRUE dominates UNKNOWN
    assert _evaluate_gate_kleene_fn("OR", 0, [T, U]) == T
    assert _evaluate_gate_kleene_fn("OR", 0, [F, U]) == U
    assert _evaluate_gate_kleene_fn("OR", 0, [F, F]) == F

    # K_OF_N (2-of-3): short-circuit TRUE at 2 TRUEs, short-circuit FALSE at 2 FALSEs
    assert _evaluate_gate_kleene_fn("K_OF_N", 2, [T, T, U]) == T
    assert _evaluate_gate_kleene_fn("K_OF_N", 2, [F, F, U]) == F
    assert _evaluate_gate_kleene_fn("K_OF_N", 2, [T, F, U]) == U
    assert _evaluate_gate_kleene_fn("K_OF_N", 2, [U, U, U]) == U


def test_showcase_circuit1_short_circuit_pruning_and_settlement(env):
    _mount_all_fixtures(env)
    c = KleeneGate(["raw.githubusercontent.com"])

    env.set_caller(SPONSOR, value=500)
    c.create_circuit("REL-PASS", BENEFICIARY, u256(600), json.dumps(_showcase_circuit_spec("security_clean.json", "v3.4.0")))

    def mock_llm(prompt: str) -> dict:
        if "atom 'A_AUDIT'" in prompt:
            return {
                "verdict": "CONTRADICTED",
                "quote": "Release v3.4.0 FAILED the automated security audit",
            }
        if "atom 'B_REV1'" in prompt:
            return {
                "verdict": "HOLDS",
                "quote": "Independent reviewer Alpha formally APPROVED release v3.4.0",
            }
        if "atom 'B_REV2'" in prompt:
            return {
                "verdict": "HOLDS",
                "quote": "Independent reviewer Beta formally APPROVED release v3.4.0",
            }
        if "atom 'V_EXPLOIT'" in prompt:
            return {
                "verdict": "CONTRADICTED",
                "quote": "explicitly confirms NO active signing-key compromise",
            }
        raise AssertionError(f"Unexpected LLM call for prompt: {prompt[:120]}")

    env.llm_handler = mock_llm
    env.set_caller(EVALUATOR, value=0)

    # 1. A_AUDIT fails -> G_FAST immediately becomes FALSE -> A_FORMAL is PRUNED!
    r1 = c.evaluate_atom("REL-PASS", "A_AUDIT")
    assert r1["envelope"]["verdict"] == "CONTRADICTED"
    assert r1["root_kleene_value"] == int(KLEENE_UNKNOWN)
    assert r1["pruned_atoms"] == ["A_FORMAL"]
    assert "A_FORMAL" not in r1["active_frontier"]

    # Guard: Evaluating pruned A_FORMAL MUST revert with ZERO web/LLM calls!
    web_before, llm_before = env.web_call_count, env.llm_call_count
    with pytest.raises(UserError, match="EXPECTED:ATOM_ALREADY_PRUNED"):
        c.evaluate_atom("REL-PASS", "A_FORMAL")
    assert env.web_call_count == web_before
    assert env.llm_call_count == llm_before

    # 2. Fallback OR -> K_OF_N(2-of-3): B_REV1 + B_REV2 pass -> G_QUORUM & G_PATH become TRUE -> B_REV3 PRUNED!
    r2 = c.evaluate_atom("REL-PASS", "B_REV1")
    assert r2["root_kleene_value"] == int(KLEENE_UNKNOWN)
    r3 = c.evaluate_atom("REL-PASS", "B_REV2")
    assert r3["root_kleene_value"] == int(KLEENE_UNKNOWN)
    assert r3["active_frontier"] == ["V_EXPLOIT"]
    assert r3["pruned_atoms"] == ["A_FORMAL", "B_REV3"]

    # Guard: Evaluating pruned B_REV3 MUST revert with ZERO web/LLM calls!
    web_before, llm_before = env.web_call_count, env.llm_call_count
    with pytest.raises(UserError, match="EXPECTED:ATOM_ALREADY_PRUNED"):
        c.evaluate_atom("REL-PASS", "B_REV3")
    assert env.web_call_count == web_before
    assert env.llm_call_count == llm_before

    # Guard: Beneficiary cannot withdraw while NOT(V_EXPLOIT) is still UNKNOWN
    env.set_caller(BENEFICIARY, value=0)
    with pytest.raises(UserError, match="EXPECTED:NOTHING_TO_WITHDRAW"):
        c.withdraw()

    # 3. V_EXPLOIT is CONTRADICTED (no exploit) -> NOT(FALSE) = TRUE -> ROOT = TRUE -> DECIDED_TRUE!
    env.set_caller(EVALUATOR, value=0)
    r4 = c.evaluate_atom("REL-PASS", "V_EXPLOIT")
    assert r4["root_kleene_value"] == int(KLEENE_TRUE)
    assert r4["circuit_status"] == int(CIRCUIT_DECIDED_TRUE)
    assert r4["active_frontier"] == []

    # Only 4 of 6 atoms were ever evaluated (2 structurally pruned!)
    view = c.get_circuit("REL-PASS")
    assert view["atoms_evaluated_count"] == 4
    assert view["atoms_pruned_count"] == 2
    assert c.get_withdrawable_balance(BENEFICIARY) == u256(500)
    assert c.get_withdrawable_balance(SPONSOR) == u256(0)

    # Beneficiary withdraws cleanly
    env.set_caller(BENEFICIARY, value=0)
    paid = c.withdraw()
    assert paid == u256(500)
    assert len(env.emitted_transfers) == 1
    assert env.emitted_transfers[0].recipient == BENEFICIARY
    assert env.emitted_transfers[0].value == u256(500)


def test_showcase_circuit2_early_veto_kill_without_evaluating_positive_branch(env):
    _mount_all_fixtures(env)
    c = KleeneGate(["raw.githubusercontent.com"])

    env.set_caller(SPONSOR, value=300)
    c.create_circuit("REL-VETO", BENEFICIARY, u256(600), json.dumps(_showcase_circuit_spec("security_compromise.json", "v3.4.1")))

    env.llm_handler = lambda p: {
        "verdict": "HOLDS",
        "quote": "confirmed active signing-key compromise and critical exploit",
    }
    env.set_caller(EVALUATOR, value=0)

    # Single evaluation of V_EXPLOIT = HOLDS -> NOT(TRUE) = FALSE -> ROOT = FALSE immediately!
    r = c.evaluate_atom("REL-VETO", "V_EXPLOIT")
    assert r["root_kleene_value"] == int(KLEENE_FALSE)
    assert r["circuit_status"] == int(CIRCUIT_DECIDED_FALSE)
    assert r["active_frontier"] == []
    assert len(r["pruned_atoms"]) == 5

    # Attempting to evaluate any positive atom reverts immediately
    with pytest.raises(UserError, match="EXPECTED:CIRCUIT_ALREADY_FINAL"):
        c.evaluate_atom("REL-VETO", "B_REV1")

    # Sponsor receives full 300 wei refund; Beneficiary gets 0
    assert c.get_withdrawable_balance(SPONSOR) == u256(300)
    assert c.get_withdrawable_balance(BENEFICIARY) == u256(0)


def test_showcase_circuit3_fail_closed_not_unknown_and_deadline_expiry(env):
    _mount_all_fixtures(env)
    c = KleeneGate(["raw.githubusercontent.com"])

    start_ts = 1763500000
    env.set_time(start_ts)
    env.set_caller(SPONSOR, value=200)
    c.create_circuit("REL-FAILCLOSED", BENEFICIARY, u256(60), json.dumps(_showcase_circuit_spec("security_ambiguous_injection.json", "v3.4.2")))

    def mock_llm(prompt: str) -> dict:
        if "atom 'B_REV1'" in prompt:
            return {"verdict": "HOLDS", "quote": "Independent reviewer Alpha formally APPROVED release v3.4.0"}
        if "atom 'B_REV2'" in prompt:
            return {"verdict": "HOLDS", "quote": "Independent reviewer Beta formally APPROVED release v3.4.0"}
        if "atom 'V_EXPLOIT'" in prompt:
            return {"verdict": "UNCLEAR", "quote": ""}
        raise AssertionError("Unexpected atom evaluation")

    env.llm_handler = mock_llm
    env.set_caller(EVALUATOR, value=0)

    # Positive branch passes via 2-of-3
    c.evaluate_atom("REL-FAILCLOSED", "B_REV1")
    c.evaluate_atom("REL-FAILCLOSED", "B_REV2")

    # V_EXPLOIT returns UNCLEAR (prompt injection / ambiguous) -> NOT(UNKNOWN) MUST STAY UNKNOWN!
    r_u1 = c.evaluate_atom("REL-FAILCLOSED", "V_EXPLOIT")
    assert r_u1["envelope"]["verdict"] == "UNCLEAR"
    assert r_u1["root_kleene_value"] == int(KLEENE_UNKNOWN)
    assert r_u1["circuit_status"] == int(CIRCUIT_UNDECIDED)
    assert r_u1["active_frontier"] == ["V_EXPLOIT"]  # retriable once before deadline

    # Second attempt still UNCLEAR -> reaches MAX_ATOM_ATTEMPTS=2, STILL not pruned!
    r_u2 = c.evaluate_atom("REL-FAILCLOSED", "V_EXPLOIT")
    assert r_u2["circuit_status"] == int(CIRCUIT_UNDECIDED)
    assert r_u2["active_frontier"] == []
    assert "V_EXPLOIT" not in r_u2["pruned_atoms"]  # exhausted, NOT structurally pruned

    # Third attempt rejected with MAX_ATTEMPTS_REACHED
    with pytest.raises(UserError, match="EXPECTED:ATOM_MAX_ATTEMPTS_REACHED"):
        c.evaluate_atom("REL-FAILCLOSED", "V_EXPLOIT")

    # Cannot expire before deadline
    with pytest.raises(UserError, match="EXPECTED:CIRCUIT_NOT_EXPIRED"):
        c.expire_circuit("REL-FAILCLOSED")

    # Advance past deadline: evaluate_atom rejected, permissionless expire_circuit refunds Sponsor
    env.set_time(start_ts + 61)
    with pytest.raises(UserError, match="EXPECTED:CIRCUIT_EXPIRED"):
        c.evaluate_atom("REL-FAILCLOSED", "A_AUDIT")

    exp_res = c.expire_circuit("REL-FAILCLOSED")
    assert exp_res["circuit_status"] == int(CIRCUIT_EXPIRED_REFUNDED)
    assert exp_res["refunded_wei"] == 200
    assert c.get_withdrawable_balance(SPONSOR) == u256(200)
    assert c.get_withdrawable_balance(BENEFICIARY) == u256(0)


def test_shared_atom_dag_stays_active_when_only_one_parent_short_circuits(env):
    """
    Shared-DAG test:
      G_ROOT = OR( G_LEFT, G_RIGHT )
        G_LEFT  = AND( A_FAIL, A_SHARED )
        G_RIGHT = AND( A_PASS, A_SHARED )
    When A_FAIL = FALSE, G_LEFT becomes FALSE, yet A_SHARED MUST remain on
    active_frontier because G_RIGHT is still UNKNOWN!
    """
    _mount_all_fixtures(env)
    c = KleeneGate(["raw.githubusercontent.com"])

    dag_spec = {
        "root_gate_id": "G_ROOT",
        "atoms": [
            {"id": "A_FAIL", "evidence_url": _url("audit_failed.json"), "claim": "Audit passed for v3.4.0."},
            {"id": "A_PASS", "evidence_url": _url("review_alpha_pass.json"), "claim": "Reviewer Alpha approved v3.4.0."},
            {"id": "A_SHARED", "evidence_url": _url("review_beta_pass.json"), "claim": "Reviewer Beta approved v3.4.0."},
        ],
        "gates": [
            {"id": "G_LEFT", "op": "AND", "children": ["A_FAIL", "A_SHARED"]},
            {"id": "G_RIGHT", "op": "AND", "children": ["A_PASS", "A_SHARED"]},
            {"id": "G_ROOT", "op": "OR", "children": ["G_LEFT", "G_RIGHT"]},
        ],
    }

    env.set_caller(SPONSOR, value=100)
    c.create_circuit("DAG-SHARED", BENEFICIARY, u256(300), json.dumps(dag_spec))

    def mock_llm(prompt: str) -> dict:
        if "atom 'A_FAIL'" in prompt:
            return {"verdict": "CONTRADICTED", "quote": "Release v3.4.0 FAILED the automated security audit"}
        if "atom 'A_PASS'" in prompt:
            return {"verdict": "HOLDS", "quote": "Independent reviewer Alpha formally APPROVED release v3.4.0"}
        return {"verdict": "HOLDS", "quote": "Independent reviewer Beta formally APPROVED release v3.4.0"}

    env.llm_handler = mock_llm
    env.set_caller(EVALUATOR, value=0)

    r1 = c.evaluate_atom("DAG-SHARED", "A_FAIL")
    assert r1["root_kleene_value"] == int(KLEENE_UNKNOWN)
    assert "A_SHARED" in r1["active_frontier"]
    assert r1["pruned_atoms"] == []

    c.evaluate_atom("DAG-SHARED", "A_PASS")
    r3 = c.evaluate_atom("DAG-SHARED", "A_SHARED")
    assert r3["root_kleene_value"] == int(KLEENE_TRUE)
    assert r3["circuit_status"] == int(CIRCUIT_DECIDED_TRUE)


def test_k_of_n_unreachable_quorum_short_circuits_false_and_prunes_remaining(env):
    """In K_OF_N(2; X1, X2, X3), two FALSE atoms kill the quorum immediately and prune X3."""
    _mount_all_fixtures(env)
    c = KleeneGate(["raw.githubusercontent.com"])

    spec = {
        "root_gate_id": "G_QUORUM",
        "atoms": [
            {"id": "X1", "evidence_url": _url("audit_failed.json"), "claim": "Audit 1 passed with zero findings."},
            {"id": "X2", "evidence_url": _url("security_clean.json"), "claim": "Active key compromise confirmed for v3.4.0."},
            {"id": "X3", "evidence_url": _url("review_alpha_pass.json"), "claim": "Reviewer Alpha approved release v3.4.0."},
        ],
        "gates": [
            {"id": "G_QUORUM", "op": "K_OF_N", "k": 2, "children": ["X1", "X2", "X3"]},
        ],
    }

    env.set_caller(SPONSOR, value=150)
    c.create_circuit("QUORUM-FAIL", BENEFICIARY, u256(300), json.dumps(spec))

    def mock_llm(prompt: str) -> dict:
        if "atom 'X1'" in prompt:
            return {"verdict": "CONTRADICTED", "quote": "Release v3.4.0 FAILED the automated security audit"}
        return {"verdict": "CONTRADICTED", "quote": "explicitly confirms NO active signing-key compromise"}

    env.llm_handler = mock_llm
    env.set_caller(EVALUATOR, value=0)

    r1 = c.evaluate_atom("QUORUM-FAIL", "X1")
    assert r1["circuit_status"] == int(CIRCUIT_UNDECIDED)
    r2 = c.evaluate_atom("QUORUM-FAIL", "X2")
    assert r2["root_kleene_value"] == int(KLEENE_FALSE)
    assert r2["circuit_status"] == int(CIRCUIT_DECIDED_FALSE)
    assert r2["pruned_atoms"] == ["X3"]
    assert c.get_withdrawable_balance(SPONSOR) == u256(150)
