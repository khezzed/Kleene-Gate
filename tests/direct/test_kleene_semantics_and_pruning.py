import json
import pathlib
import pytest
from conftest import MockWebResponse, UserError, u256
from kleene_gate import (
    CIRCUIT_DECIDED_FALSE,
    CIRCUIT_DECIDED_TRUE,
    CIRCUIT_EXPIRED_REFUNDED,
    CIRCUIT_UNDECIDED,
    CIRCUIT_UNSATISFIABLE,
    KLEENE_FALSE,
    KLEENE_TRUE,
    KLEENE_UNKNOWN,
    KleeneGate,
    _evaluate_gate_kleene_fn,
    _evaluate_gate_possibility_fn,
)

SPONSOR = "0x1111111111111111111111111111111111111111"
BENEFICIARY = "0x2222222222222222222222222222222222222222"
EVALUATOR = "0x3333333333333333333333333333333333333333"
PINNED_SHA = "b" * 40
FIXTURES_DIR = pathlib.Path(__file__).resolve().parents[2] / "fixtures" / "evidence"


def _url(fname: str) -> str:
    return f"https://raw.githubusercontent.com/khezzed/Kleene-Gate/{PINNED_SHA}/fixtures/evidence/{fname}"


def _mount_all_fixtures(env) -> None:
    for p in FIXTURES_DIR.glob("*.md"):
        env.web_responses[_url(p.name)] = MockWebResponse(status=200, body=p.read_bytes())


def _showcase_circuit_spec(veto_fixture: str, release_ver: str) -> dict:
    return {
        "root_gate_id": "G_ROOT",
        "atoms": [
            {
                "id": "A_AUDIT",
                "evidence_url": _url("audit_report_v340.md"),
                "claim": "The security audit memo for release v3.4.0 concludes that the audit passed with no unresolved high-severity findings.",
            },
            {
                "id": "A_FORMAL",
                "evidence_url": _url("formal_verification_v340.md"),
                "claim": "Formal verification for release v3.4.0 passed all safety invariants with zero counterexamples.",
            },
            {
                "id": "B_REV1",
                "evidence_url": _url("review_alpha_v340.md"),
                "claim": "Reviewer Alpha formally approves release v3.4.0 for production rollout after verifying all regression tests passed.",
            },
            {
                "id": "B_REV2",
                "evidence_url": _url("review_beta_v340.md"),
                "claim": "Reviewer Beta formally approves release v3.4.0 for deployment after verifying access-control and accounting invariants.",
            },
            {
                "id": "B_REV3",
                "evidence_url": _url("review_gamma_v340.md"),
                "claim": "Reviewer Gamma formally approves release v3.4.0.",
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


def test_exact_kleene_and_possibility_truth_tables():
    U, T, F = int(KLEENE_UNKNOWN), int(KLEENE_TRUE), int(KLEENE_FALSE)

    # Pure Kleene 3-valued logic
    assert _evaluate_gate_kleene_fn("NOT", 0, [T]) == F
    assert _evaluate_gate_kleene_fn("NOT", 0, [F]) == T
    assert _evaluate_gate_kleene_fn("NOT", 0, [U]) == U
    assert _evaluate_gate_kleene_fn("AND", 0, [F, U]) == F
    assert _evaluate_gate_kleene_fn("AND", 0, [T, U]) == U
    assert _evaluate_gate_kleene_fn("OR", 0, [T, U]) == T
    assert _evaluate_gate_kleene_fn("OR", 0, [F, U]) == U
    assert _evaluate_gate_kleene_fn("K_OF_N", 2, [T, T, U]) == T
    assert _evaluate_gate_kleene_fn("K_OF_N", 2, [F, F, U]) == F
    assert _evaluate_gate_kleene_fn("K_OF_N", 2, [T, F, U]) == U

    # Possibility-interval propagation with exhausted UNKNOWN (can_t=False, can_f=False)
    # K_OF_N(2; B1_exhausted, B2_false, B3_evaluable): can_t=False, can_f=True
    ct, cf = _evaluate_gate_possibility_fn("K_OF_N", 2, [False, False, True], [False, True, True])
    assert ct is False and cf is True
    # Wrapping inside NOT swaps (can_t, can_f) -> (True, False): does NOT fail open!
    assert _evaluate_gate_possibility_fn("NOT", 0, [ct], [cf]) == (True, False)


def test_showcase_circuit1_short_circuit_pruning_and_settlement(env):
    _mount_all_fixtures(env)
    c = KleeneGate(["raw.githubusercontent.com"])

    env.set_caller(SPONSOR, value=500)
    c.create_circuit("REL-PASS", BENEFICIARY, u256(600), json.dumps(_showcase_circuit_spec("security_bulletin_v340.md", "v3.4.0")))

    def mock_llm(prompt: str) -> dict:
        if "atom 'A_AUDIT'" in prompt:
            return {"verdict": "CONTRADICTED", "quote": "marks the automated security audit for release v3.4.0 as failed"}
        if "atom 'B_REV1'" in prompt:
            return {"verdict": "HOLDS", "quote": "Reviewer Alpha formally approves release v3.4.0 for production rollout"}
        if "atom 'B_REV2'" in prompt:
            return {"verdict": "HOLDS", "quote": "Reviewer Beta formally approves release v3.4.0 for deployment"}
        if "atom 'V_EXPLOIT'" in prompt:
            return {"verdict": "CONTRADICTED", "quote": "there is no active signing-key compromise and no critical exploit"}
        raise AssertionError(f"Unexpected LLM call for prompt: {prompt[:120]}")

    env.llm_handler = mock_llm
    env.set_caller(EVALUATOR, value=0)

    r1 = c.evaluate_atom("REL-PASS", "A_AUDIT")
    assert r1["envelope"]["verdict"] == "CONTRADICTED"
    assert r1["root_kleene_value"] == int(KLEENE_UNKNOWN)
    assert r1["pruned_atoms"] == ["A_FORMAL"]

    web_before, llm_before = env.web_call_count, env.llm_call_count
    with pytest.raises(UserError, match="EXPECTED:ATOM_ALREADY_PRUNED"):
        c.evaluate_atom("REL-PASS", "A_FORMAL")
    assert env.web_call_count == web_before and env.llm_call_count == llm_before

    c.evaluate_atom("REL-PASS", "B_REV1")
    r3 = c.evaluate_atom("REL-PASS", "B_REV2")
    assert r3["active_frontier"] == ["V_EXPLOIT"]
    assert r3["pruned_atoms"] == ["A_FORMAL", "B_REV3"]

    web_before, llm_before = env.web_call_count, env.llm_call_count
    with pytest.raises(UserError, match="EXPECTED:ATOM_ALREADY_PRUNED"):
        c.evaluate_atom("REL-PASS", "B_REV3")
    assert env.web_call_count == web_before and env.llm_call_count == llm_before

    env.set_caller(BENEFICIARY, value=0)
    with pytest.raises(UserError, match="EXPECTED:NOTHING_TO_WITHDRAW"):
        c.withdraw()

    env.set_caller(EVALUATOR, value=0)
    r4 = c.evaluate_atom("REL-PASS", "V_EXPLOIT")
    assert r4["root_kleene_value"] == int(KLEENE_TRUE)
    assert r4["circuit_status"] == int(CIRCUIT_DECIDED_TRUE)

    view = c.get_circuit("REL-PASS")
    assert view["atoms_evaluated_count"] == 4 and view["atoms_pruned_count"] == 2

    env.set_caller(BENEFICIARY, value=0)
    assert c.withdraw() == u256(500)


def test_showcase_circuit2_early_veto_kill_without_evaluating_positive_branch(env):
    _mount_all_fixtures(env)
    c = KleeneGate(["raw.githubusercontent.com"])

    env.set_caller(SPONSOR, value=300)
    c.create_circuit("REL-VETO", BENEFICIARY, u256(600), json.dumps(_showcase_circuit_spec("security_bulletin_v341.md", "v3.4.1")))

    env.llm_handler = lambda p: {
        "verdict": "HOLDS",
        "quote": "confirmed an active compromise of the v3.4.1 release signing key",
    }
    env.set_caller(EVALUATOR, value=0)

    r = c.evaluate_atom("REL-VETO", "V_EXPLOIT")
    assert r["root_kleene_value"] == int(KLEENE_FALSE)
    assert r["circuit_status"] == int(CIRCUIT_DECIDED_FALSE)
    assert len(r["pruned_atoms"]) == 5

    with pytest.raises(UserError, match="EXPECTED:CIRCUIT_ALREADY_FINAL"):
        c.evaluate_atom("REL-VETO", "B_REV1")
    assert c.get_withdrawable_balance(SPONSOR) == u256(300)


def test_fail_closed_not_unknown_attempt1_expiry_and_attempt2_unsatisfiable(env):
    _mount_all_fixtures(env)
    c = KleeneGate(["raw.githubusercontent.com"])

    spec = {
        "root_gate_id": "G_ROOT",
        "atoms": [
            {"id": "B_REV1", "evidence_url": _url("review_alpha_v340.md"), "claim": "Reviewer Alpha formally approves release v3.4.0."},
            {"id": "V_EXPLOIT", "evidence_url": _url("runner_maintenance_note.md"), "claim": "Security bulletin confirms active exploit on release v3.4.2."},
        ],
        "gates": [
            {"id": "G_NO_VETO", "op": "NOT", "children": ["V_EXPLOIT"]},
            {"id": "G_ROOT", "op": "AND", "children": ["B_REV1", "G_NO_VETO"]},
        ],
    }

    t0 = 1763500000
    env.set_time(t0)
    env.set_caller(SPONSOR, value=200)
    c.create_circuit("C-EXP", BENEFICIARY, u256(60), json.dumps(spec))
    c.create_circuit("C-UNSAT", BENEFICIARY, u256(600), json.dumps(spec))

    def mock_llm(prompt: str) -> dict:
        if "atom 'B_REV1'" in prompt:
            return {"verdict": "HOLDS", "quote": "Reviewer Alpha formally approves release v3.4.0"}
        return {"verdict": "UNCLEAR", "quote": ""}

    env.llm_handler = mock_llm
    env.set_caller(EVALUATOR, value=0)

    # C-EXP: Attempt 1 UNCLEAR keeps circuit UNDECIDED (NOT(UNKNOWN)==UNKNOWN), expires past deadline
    c.evaluate_atom("C-EXP", "B_REV1")
    r1 = c.evaluate_atom("C-EXP", "V_EXPLOIT")
    assert r1["circuit_status"] == int(CIRCUIT_UNDECIDED)
    assert r1["root_kleene_value"] == int(KLEENE_UNKNOWN)
    assert r1["root_can_be_true"] is True

    with pytest.raises(UserError, match="EXPECTED:CIRCUIT_NOT_EXPIRED"):
        c.expire_circuit("C-EXP")

    env.set_time(t0 + 61)
    exp = c.expire_circuit("C-EXP")
    assert exp["circuit_status"] == int(CIRCUIT_EXPIRED_REFUNDED)

    # C-UNSAT: Attempt 2 UNCLEAR exhausts V_EXPLOIT -> can_be_true(ROOT)==False -> immediate CIRCUIT_UNSATISFIABLE!
    c.evaluate_atom("C-UNSAT", "B_REV1")
    c.evaluate_atom("C-UNSAT", "V_EXPLOIT")
    r2 = c.evaluate_atom("C-UNSAT", "V_EXPLOIT")
    assert r2["root_kleene_value"] == int(KLEENE_UNKNOWN)
    assert r2["root_can_be_true"] is False
    assert r2["circuit_status"] == int(CIRCUIT_UNSATISFIABLE)
    assert c.get_withdrawable_balance(SPONSOR) == u256(400)


def test_k_of_n_exhausted_unclear_atom_makes_quorum_unsatisfiable_and_prunes_b3(env):
    """
    In K_OF_N(2; U_EXHAUST, F_FAIL, P_UNUSED):
      - F_FAIL = FALSE
      - U_EXHAUST hits UNCLEAR twice (permanently exhausted -> can_t=False, can_f=False)
      - Max possible TRUE count = 1 (P_UNUSED only) < 2 => immediately CIRCUIT_UNSATISFIABLE!
      - P_UNUSED is pruned without ever running LLM.
    """
    _mount_all_fixtures(env)
    c = KleeneGate(["raw.githubusercontent.com"])

    spec = {
        "root_gate_id": "G_QUORUM",
        "atoms": [
            {"id": "U_EXHAUST", "evidence_url": _url("runner_maintenance_note.md"), "claim": "Security clearance confirmed for v3.4.2."},
            {"id": "F_FAIL", "evidence_url": _url("audit_report_v340.md"), "claim": "Audit for v3.4.0 passed with zero findings."},
            {"id": "P_UNUSED", "evidence_url": _url("review_alpha_v340.md"), "claim": "Reviewer Alpha approved v3.4.0."},
        ],
        "gates": [
            {"id": "G_QUORUM", "op": "K_OF_N", "k": 2, "children": ["U_EXHAUST", "F_FAIL", "P_UNUSED"]},
        ],
    }

    env.set_caller(SPONSOR, value=150)
    c.create_circuit("QUORUM-UNSAT", BENEFICIARY, u256(600), json.dumps(spec))

    def mock_llm(prompt: str) -> dict:
        if "atom 'F_FAIL'" in prompt:
            return {"verdict": "CONTRADICTED", "quote": "marks the automated security audit for release v3.4.0 as failed"}
        if "atom 'U_EXHAUST'" in prompt:
            return {"verdict": "UNCLEAR", "quote": ""}
        raise AssertionError("P_UNUSED must NEVER be evaluated!")

    env.llm_handler = mock_llm
    env.set_caller(EVALUATOR, value=0)

    c.evaluate_atom("QUORUM-UNSAT", "F_FAIL")
    r_att1 = c.evaluate_atom("QUORUM-UNSAT", "U_EXHAUST")
    assert r_att1["circuit_status"] == int(CIRCUIT_UNDECIDED)

    r_att2 = c.evaluate_atom("QUORUM-UNSAT", "U_EXHAUST")
    assert r_att2["root_kleene_value"] == int(KLEENE_UNKNOWN)
    assert r_att2["root_can_be_true"] is False
    assert r_att2["circuit_status"] == int(CIRCUIT_UNSATISFIABLE)
    assert r_att2["pruned_atoms"] == ["P_UNUSED"]
    assert c.get_withdrawable_balance(SPONSOR) == u256(150)

    with pytest.raises(UserError, match="EXPECTED:CIRCUIT_ALREADY_FINAL"):
        c.evaluate_atom("QUORUM-UNSAT", "P_UNUSED")


def test_negated_k_of_n_with_exhausted_atom_is_fail_closed_and_sound(env):
    """
    Soundness under NOT: ROOT = NOT( K_OF_N(2; U_EXHAUST, F_FAIL, P_DECIDER) )
    After F_FAIL=FALSE and U_EXHAUST exhausted at UNKNOWN:
      - K_OF_N has kleene=U, can_t=False, can_f=True (because P_DECIDER=FALSE gives 2 FALSEs > 1).
      - Therefore ROOT = NOT(K_OF_N) has can_t=True! Must NOT fail open AND must keep P_DECIDER active!
      - Path 1: P_DECIDER = FALSE => K_OF_N = FALSE => NOT(FALSE) = TRUE => Beneficiary wins!
      - Path 2: P_DECIDER = TRUE  => K_OF_N stays U permanently (can_t=False, can_f=False) =>
                ROOT becomes CIRCUIT_UNSATISFIABLE => Sponsor refunded (never fails open)!
    """
    _mount_all_fixtures(env)
    c = KleeneGate(["raw.githubusercontent.com"])

    spec = {
        "root_gate_id": "G_ROOT",
        "atoms": [
            {"id": "U_EXHAUST", "evidence_url": _url("runner_maintenance_note.md"), "claim": "Security clearance confirmed for v3.4.2."},
            {"id": "F_FAIL", "evidence_url": _url("audit_report_v340.md"), "claim": "Audit for v3.4.0 passed with zero findings."},
            {"id": "P_DECIDER", "evidence_url": _url("security_bulletin_v340.md"), "claim": "Active key compromise exists on v3.4.0."},
        ],
        "gates": [
            {"id": "G_Q", "op": "K_OF_N", "k": 2, "children": ["U_EXHAUST", "F_FAIL", "P_DECIDER"]},
            {"id": "G_ROOT", "op": "NOT", "children": ["G_Q"]},
        ],
    }

    env.set_caller(SPONSOR, value=100)
    c.create_circuit("NOT-Q-PASS", BENEFICIARY, u256(600), json.dumps(spec))
    c.create_circuit("NOT-Q-FAIL", BENEFICIARY, u256(600), json.dumps(spec))

    def setup_exhausted(cid: str):
        env.llm_handler = lambda p: (
            {"verdict": "CONTRADICTED", "quote": "marks the automated security audit for release v3.4.0 as failed"}
            if "atom 'F_FAIL'" in p
            else {"verdict": "UNCLEAR", "quote": ""}
        )
        env.set_caller(EVALUATOR, value=0)
        c.evaluate_atom(cid, "F_FAIL")
        c.evaluate_atom(cid, "U_EXHAUST")
        r = c.evaluate_atom(cid, "U_EXHAUST")
        assert r["circuit_status"] == int(CIRCUIT_UNDECIDED)
        assert r["root_can_be_true"] is True
        assert r["active_frontier"] == ["P_DECIDER"]

    # Path 1: P_DECIDER = FALSE -> G_Q = FALSE -> NOT(FALSE) = TRUE -> DECIDED_TRUE
    setup_exhausted("NOT-Q-PASS")
    env.llm_handler = lambda p: {"verdict": "CONTRADICTED", "quote": "there is no active signing-key compromise"}
    rp = c.evaluate_atom("NOT-Q-PASS", "P_DECIDER")
    assert rp["circuit_status"] == int(CIRCUIT_DECIDED_TRUE)
    assert c.get_withdrawable_balance(BENEFICIARY) == u256(100)

    # Path 2: P_DECIDER = TRUE -> G_Q stays UNKNOWN permanently -> CIRCUIT_UNSATISFIABLE (fail-closed!)
    setup_exhausted("NOT-Q-FAIL")
    env.llm_handler = lambda p: {"verdict": "HOLDS", "quote": "Earlier today, an automated telemetry monitor"}
    rf = c.evaluate_atom("NOT-Q-FAIL", "P_DECIDER")
    assert rf["root_kleene_value"] == int(KLEENE_UNKNOWN)
    assert rf["circuit_status"] == int(CIRCUIT_UNSATISFIABLE)
    assert c.get_withdrawable_balance(SPONSOR) == u256(100)


def test_shared_atom_dag_stays_active_when_only_one_parent_short_circuits(env):
    _mount_all_fixtures(env)
    c = KleeneGate(["raw.githubusercontent.com"])

    dag_spec = {
        "root_gate_id": "G_ROOT",
        "atoms": [
            {"id": "A_FAIL", "evidence_url": _url("audit_report_v340.md"), "claim": "Audit passed for v3.4.0."},
            {"id": "A_PASS", "evidence_url": _url("review_alpha_v340.md"), "claim": "Reviewer Alpha approved v3.4.0."},
            {"id": "A_SHARED", "evidence_url": _url("review_beta_v340.md"), "claim": "Reviewer Beta approved v3.4.0."},
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
            return {"verdict": "CONTRADICTED", "quote": "marks the automated security audit for release v3.4.0 as failed"}
        if "atom 'A_PASS'" in prompt:
            return {"verdict": "HOLDS", "quote": "Reviewer Alpha formally approves release v3.4.0"}
        return {"verdict": "HOLDS", "quote": "Reviewer Beta formally approves release v3.4.0"}

    env.llm_handler = mock_llm
    env.set_caller(EVALUATOR, value=0)

    r1 = c.evaluate_atom("DAG-SHARED", "A_FAIL")
    assert "A_SHARED" in r1["active_frontier"]
    c.evaluate_atom("DAG-SHARED", "A_PASS")
    r3 = c.evaluate_atom("DAG-SHARED", "A_SHARED")
    assert r3["circuit_status"] == int(CIRCUIT_DECIDED_TRUE)
