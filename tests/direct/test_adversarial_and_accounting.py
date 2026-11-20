import json
import pytest
from conftest import ConsensusDisagreementError, MockWebResponse, UserError, u256
from kleene_gate import (
    CIRCUIT_CANCELLED,
    CIRCUIT_DECIDED_FALSE,
    CIRCUIT_DECIDED_TRUE,
    CIRCUIT_EXPIRED_REFUNDED,
    CIRCUIT_UNSATISFIABLE,
    FETCH_ACCESS_DENIED,
    FETCH_HTTP_ERROR,
    FETCH_INVALID_UTF8,
    FETCH_NOT_FOUND,
    FETCH_OK,
    FETCH_REDIRECT_BLOCKED,
    FETCH_TOO_LARGE,
    FETCH_TOO_SMALL,
    KleeneGate,
)

SPONSOR = "0x1111111111111111111111111111111111111111"
BENEFICIARY = "0x2222222222222222222222222222222222222222"
STRANGER = "0x4444444444444444444444444444444444444444"
PINNED_SHA = "c" * 40


def _url(name: str) -> str:
    return f"https://raw.githubusercontent.com/khezzed/Kleene-Gate/{PINNED_SHA}/fixtures/{name}.json"


def _two_atom_and_spec() -> dict:
    return {
        "root_gate_id": "G_ROOT",
        "atoms": [
            {"id": "A1", "evidence_url": _url("e1"), "claim": "Release passed automated unit tests cleanly."},
            {"id": "A2", "evidence_url": _url("e2"), "claim": "Release signed by hardware release key."},
        ],
        "gates": [
            {"id": "G_ROOT", "op": "AND", "children": ["A1", "A2"]},
        ],
    }


def _valid_payload_bytes() -> bytes:
    return (
        b'{"status":"PASSED","summary":"Release passed automated unit tests cleanly with zero errors."}'
    )


# =============================================================================
# 1. Adversarial Leader Tests (Same Headline Result, Forged Field)
# =============================================================================

@pytest.mark.parametrize(
    "tamper_name,mutator",
    [
        ("forged_evidence_sha256", lambda d: {**d, "evidence_sha256": "0" * 64}),
        ("forged_http_status", lambda d: {**d, "http_status": 201}),
        ("forged_fetch_status", lambda d: {**d, "fetch_status": FETCH_NOT_FOUND}),
        ("forged_claim_sha256", lambda d: {**d, "claim_sha256": "f" * 64}),
        ("forged_atom_id", lambda d: {**d, "atom_id": "A2"}),
        ("forged_circuit_id", lambda d: {**d, "circuit_id": "OTHER"}),
        ("injected_extra_field", lambda d: {**d, "unchecked_rationale": "forged"}),
        ("missing_field", lambda d: {k: v for k, v in d.items() if k != "evidence_sha256"}),
        ("forged_headline_verdict", lambda d: {**d, "verdict": "CONTRADICTED"}),
    ],
)
def test_adversarial_leader_forged_field_rejected_by_validator(env, tamper_name, mutator):
    c = KleeneGate(["raw.githubusercontent.com"])
    env.set_caller(SPONSOR, value=100)
    c.create_circuit("ADV-1", BENEFICIARY, u256(300), json.dumps(_two_atom_and_spec()))

    env.web_responses[_url("e1")] = MockWebResponse(status=200, body=_valid_payload_bytes())
    env.llm_handler = lambda p: {
        "verdict": "HOLDS",
        "quote": "Release passed automated unit tests cleanly",
    }
    env.adversarial_leader_override = mutator

    env.set_caller(STRANGER, value=0)
    with pytest.raises(ConsensusDisagreementError):
        c.evaluate_atom("ADV-1", "A1")

    # Atom state must remain completely untouched after consensus rejection
    atom_view = c.get_atom("ADV-1", "A1")
    assert atom_view["verdict"] == "UNEVALUATED"
    assert atom_view["attempts"] == 0


# =============================================================================
# 2. Evidence Failures (Non-200, Redirect, Empty, Oversized, Invalid UTF-8, Bad LLM)
# =============================================================================

@pytest.mark.parametrize(
    "mock_resp,expected_http,expected_fetch",
    [
        (MockWebResponse(status=404, body=b"not found"), 404, FETCH_NOT_FOUND),
        (MockWebResponse(status=403, body=b"forbidden"), 403, FETCH_ACCESS_DENIED),
        (MockWebResponse(status=500, body=b"internal error"), 500, FETCH_HTTP_ERROR),
        (MockWebResponse(status=302, body=b"redirect"), 302, FETCH_REDIRECT_BLOCKED),
        (RuntimeError("socket reset"), 0, FETCH_HTTP_ERROR),
        (MockWebResponse(status=200, body=b""), 200, FETCH_TOO_SMALL),
        (MockWebResponse(status=200, body=b"too short"), 200, FETCH_TOO_SMALL),
        (MockWebResponse(status=200, body=b"x" * 16385), 200, FETCH_TOO_LARGE),
        (MockWebResponse(status=200, body=b"\xff\xfe\xfd" * 20), 200, FETCH_INVALID_UTF8),
    ],
)
def test_evidence_failures_fail_closed_to_unclear(env, mock_resp, expected_http, expected_fetch):
    c = KleeneGate(["raw.githubusercontent.com"])
    env.set_caller(SPONSOR, value=100)
    c.create_circuit("EV-FAIL", BENEFICIARY, u256(300), json.dumps(_two_atom_and_spec()))

    env.web_responses[_url("e1")] = mock_resp
    env.llm_handler = lambda p: (_ for _ in ()).throw(AssertionError("LLM must not run on bad evidence"))

    env.set_caller(STRANGER, value=0)
    res = c.evaluate_atom("EV-FAIL", "A1")
    assert res["envelope"]["verdict"] == "UNCLEAR"
    assert res["envelope"]["http_status"] == expected_http
    assert res["envelope"]["fetch_status"] == expected_fetch
    assert res["envelope"]["evidence_sha256"] == ""
    assert res["circuit_status"] == 0


def test_ungrounded_quote_and_invented_verdict_fail_closed(env):
    c = KleeneGate(["raw.githubusercontent.com"])
    env.set_caller(SPONSOR, value=100)
    c.create_circuit("BAD-LLM", BENEFICIARY, u256(300), json.dumps(_two_atom_and_spec()))
    env.web_responses[_url("e1")] = MockWebResponse(status=200, body=_valid_payload_bytes())
    env.web_responses[_url("e2")] = MockWebResponse(status=200, body=_valid_payload_bytes())

    # Attempt 1 on A1: fabricated quote NOT present in fetched bytes -> downgraded to UNCLEAR
    env.llm_handler = lambda p: {
        "verdict": "HOLDS",
        "quote": "This fabricated quote does not exist anywhere in payload",
    }
    env.set_caller(STRANGER, value=0)
    r1 = c.evaluate_atom("BAD-LLM", "A1")
    assert r1["envelope"]["fetch_status"] == FETCH_OK
    assert r1["envelope"]["verdict"] == "UNCLEAR"

    # Attempt 1 on A2: invented verdict token outside allowlist -> downgraded to UNCLEAR
    env.llm_handler = lambda p: {
        "verdict": "SUPER_APPROVED",
        "quote": "Release passed automated unit tests cleanly",
    }
    r2 = c.evaluate_atom("BAD-LLM", "A2")
    assert r2["envelope"]["fetch_status"] == FETCH_OK
    assert r2["envelope"]["verdict"] == "UNCLEAR"

    # Attempt 2 on A2: malformed non-JSON LLM output -> downgraded to UNCLEAR
    env.llm_handler = lambda p: "not json at all"
    r3 = c.evaluate_atom("BAD-LLM", "A2")
    assert r3["envelope"]["verdict"] == "UNCLEAR"


# =============================================================================
# 3. Unauthorized Callers, Anti-Rugpull, Replay & Non-Payable Guards
# =============================================================================

def test_unauthorized_cancel_anti_rugpull_replay_and_non_payable(env):
    c = KleeneGate(["raw.githubusercontent.com"])
    env.set_caller(SPONSOR, value=100)
    c.create_circuit("AUTH-1", BENEFICIARY, u256(300), json.dumps(_two_atom_and_spec()))

    # Stranger & Beneficiary cannot cancel
    env.set_caller(STRANGER, value=0)
    with pytest.raises(UserError, match="EXPECTED:UNAUTHORIZED_CALLER"):
        c.cancel_circuit("AUTH-1")

    env.set_caller(BENEFICIARY, value=0)
    with pytest.raises(UserError, match="EXPECTED:UNAUTHORIZED_CALLER"):
        c.cancel_circuit("AUTH-1")

    # Non-payable methods revert if native value is attached
    env.set_caller(SPONSOR, value=1)
    with pytest.raises(UserError, match="EXPECTED:NON_PAYABLE_METHOD"):
        c.evaluate_atom("AUTH-1", "A1")
    with pytest.raises(UserError, match="EXPECTED:NON_PAYABLE_METHOD"):
        c.cancel_circuit("AUTH-1")
    with pytest.raises(UserError, match="EXPECTED:NON_PAYABLE_METHOD"):
        c.expire_circuit("AUTH-1")
    with pytest.raises(UserError, match="EXPECTED:NON_PAYABLE_METHOD"):
        c.withdraw()

    # Once 1 atom is evaluated, even Sponsor cannot rug-pull via cancel_circuit
    env.web_responses[_url("e1")] = MockWebResponse(status=200, body=_valid_payload_bytes())
    env.llm_handler = lambda p: {
        "verdict": "HOLDS",
        "quote": "Release passed automated unit tests cleanly",
    }
    env.set_caller(STRANGER, value=0)
    c.evaluate_atom("AUTH-1", "A1")

    env.set_caller(SPONSOR, value=0)
    with pytest.raises(UserError, match="EXPECTED:CIRCUIT_EVALUATION_STARTED"):
        c.cancel_circuit("AUTH-1")

    # Replay guard on already-finalized atom A1
    env.set_caller(STRANGER, value=0)
    with pytest.raises(UserError, match="EXPECTED:ATOM_ALREADY_FINALIZED"):
        c.evaluate_atom("AUTH-1", "A1")


# =============================================================================
# 4. Multi-Circuit Accounting Conservation Invariant
# =============================================================================

def test_multi_circuit_conservation_invariant_across_all_terminal_states(env):
    c = KleeneGate(["raw.githubusercontent.com"])
    spec_str = json.dumps(_two_atom_and_spec())
    env.web_responses[_url("e1")] = MockWebResponse(status=200, body=_valid_payload_bytes())
    env.web_responses[_url("e2")] = MockWebResponse(status=200, body=_valid_payload_bytes())

    def check_conservation(expected_dep: int, expected_locked: int, expected_wd_able: int, expected_wd: int) -> None:
        a = c.get_accounting_state()
        assert a["conservation_ok"] is True
        assert a["total_deposited_wei"] == expected_dep
        assert a["total_locked_wei"] == expected_locked
        assert a["total_withdrawable_wei"] == expected_wd_able
        assert a["total_withdrawn_wei"] == expected_wd
        assert sum(int(t.value) for t in env.emitted_transfers) == expected_wd

    t0 = 1763500000
    env.set_time(t0)

    # Create 5 circuits covering ALL 5 terminal states: 100+200+300+400+50 = 1050 wei
    for cid, amt, dur in [
        ("C-TRUE", 100, 300),
        ("C-FALSE", 200, 300),
        ("C-EXP", 300, 60),
        ("C-CAN", 400, 300),
        ("C-UNSAT", 50, 300),
    ]:
        env.set_caller(SPONSOR, value=amt)
        c.create_circuit(cid, BENEFICIARY, u256(dur), spec_str)
    check_conservation(1050, 1050, 0, 0)

    # 1. C-CAN cancelled before evaluation -> Sponsor +400 withdrawable
    env.set_caller(SPONSOR, value=0)
    r_can = c.cancel_circuit("C-CAN")
    assert r_can["circuit_status"] == int(CIRCUIT_CANCELLED)
    check_conservation(1050, 650, 400, 0)

    # 2. C-TRUE passes both atoms -> Beneficiary +100 withdrawable
    env.llm_handler = lambda p: {"verdict": "HOLDS", "quote": "Release passed automated unit tests cleanly"}
    env.set_caller(STRANGER, value=0)
    c.evaluate_atom("C-TRUE", "A1")
    r_t = c.evaluate_atom("C-TRUE", "A2")
    assert r_t["circuit_status"] == int(CIRCUIT_DECIDED_TRUE)
    check_conservation(1050, 550, 500, 0)

    # 3. C-FALSE fails on A1 -> short-circuits FALSE -> Sponsor +200 withdrawable (total 600)
    env.llm_handler = lambda p: {"verdict": "CONTRADICTED", "quote": "Release passed automated unit tests cleanly"}
    r_f = c.evaluate_atom("C-FALSE", "A1")
    assert r_f["circuit_status"] == int(CIRCUIT_DECIDED_FALSE)
    check_conservation(1050, 350, 700, 0)

    # 4. C-UNSAT exhausts A1 with UNCLEAR x2 -> immediate CIRCUIT_UNSATISFIABLE -> Sponsor +50 (total 650)
    env.llm_handler = lambda p: {"verdict": "UNCLEAR", "quote": ""}
    c.evaluate_atom("C-UNSAT", "A1")
    r_u = c.evaluate_atom("C-UNSAT", "A1")
    assert r_u["circuit_status"] == int(CIRCUIT_UNSATISFIABLE)
    check_conservation(1050, 300, 750, 0)

    # 5. C-EXP expires past deadline -> Sponsor +300 withdrawable (total 950)
    env.set_time(t0 + 61)
    r_e = c.expire_circuit("C-EXP")
    assert r_e["circuit_status"] == int(CIRCUIT_EXPIRED_REFUNDED)
    check_conservation(1050, 0, 1050, 0)

    # 6. Beneficiary withdraws 100, double-withdraw reverts
    env.set_caller(BENEFICIARY, value=0)
    assert c.withdraw() == u256(100)
    check_conservation(1050, 0, 950, 100)
    with pytest.raises(UserError, match="EXPECTED:NOTHING_TO_WITHDRAW"):
        c.withdraw()

    # 7. Sponsor withdraws 950, final balance 100% drained & conserved
    env.set_caller(SPONSOR, value=0)
    assert c.withdraw() == u256(950)
    check_conservation(1050, 0, 0, 1050)
    with pytest.raises(UserError, match="EXPECTED:NOTHING_TO_WITHDRAW"):
        c.withdraw()
