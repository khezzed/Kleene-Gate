import json
import pytest
from conftest import UserError, u256
from kleene_gate import KleeneGate

SPONSOR = "0x1111111111111111111111111111111111111111"
BENEFICIARY = "0x2222222222222222222222222222222222222222"
PINNED_SHA = "a" * 40


def _gh(name: str) -> str:
    return f"https://raw.githubusercontent.com/khezzed/Kleene-Gate/{PINNED_SHA}/fixtures/evidence/{name}.json"


def _minimal_valid_spec() -> dict:
    return {
        "root_gate_id": "G_ROOT",
        "atoms": [
            {"id": "A1", "evidence_url": _gh("f1"), "claim": "Release passed automated security audit."},
            {"id": "A2", "evidence_url": _gh("f2"), "claim": "No critical exploit advisory is active."},
        ],
        "gates": [
            {"id": "G_NO_VETO", "op": "NOT", "children": ["A2"]},
            {"id": "G_ROOT", "op": "AND", "children": ["A1", "G_NO_VETO"]},
        ],
    }


def test_constructor_validation(env):
    with pytest.raises(UserError, match="EXPECTED:EMPTY_ALLOWED_DOMAINS"):
        KleeneGate([])
    with pytest.raises(UserError, match="EXPECTED:INVALID_DOMAIN"):
        KleeneGate(["not_a_host"])
    with pytest.raises(UserError, match="EXPECTED:TOO_MANY_DOMAINS"):
        KleeneGate([f"host{i}.example.com" for i in range(9)])

    c = KleeneGate(["raw.githubusercontent.com"])
    acct = c.get_accounting_state()
    assert acct["conservation_ok"] is True
    assert acct["circuit_count"] == 0


def test_create_valid_nested_circuit(env):
    c = KleeneGate(["raw.githubusercontent.com"])
    env.set_caller(SPONSOR, value=250)
    res = c.create_circuit("CIRC-1", BENEFICIARY, u256(300), json.dumps(_minimal_valid_spec()))
    assert res["circuit_id"] == "CIRC-1"
    assert res["escrow_wei"] == 250
    assert res["atom_count"] == 2
    assert res["gate_count"] == 2

    view = c.get_circuit("CIRC-1")
    assert view["status"] == 0
    assert view["root_kleene_value"] == 0
    assert view["active_frontier"] == ["A1", "A2"]
    assert view["pruned_atoms"] == []


def test_reject_direct_and_multi_hop_cycles(env):
    c = KleeneGate(["raw.githubusercontent.com"])
    env.set_caller(SPONSOR, value=100)

    # 2-gate cycle: G1 -> G2 -> G1
    cyclic_spec = {
        "root_gate_id": "G1",
        "atoms": [
            {"id": "A1", "evidence_url": _gh("f1"), "claim": "Claim one is verifiable."},
            {"id": "A2", "evidence_url": _gh("f2"), "claim": "Claim two is verifiable."},
        ],
        "gates": [
            {"id": "G1", "op": "AND", "children": ["A1", "G2"]},
            {"id": "G2", "op": "OR", "children": ["A2", "G1"]},
        ],
    }
    with pytest.raises(UserError, match="EXPECTED:CIRCUIT_CYCLE_DETECTED"):
        c.create_circuit("CYC-1", BENEFICIARY, u256(100), json.dumps(cyclic_spec))

    # Self-cycle on NOT gate: G1 -> G1
    self_cycle = {
        "root_gate_id": "G1",
        "atoms": [
            {"id": "A1", "evidence_url": _gh("f1"), "claim": "Claim one is verifiable."},
            {"id": "A2", "evidence_url": _gh("f2"), "claim": "Claim two is verifiable."},
        ],
        "gates": [
            {"id": "G1", "op": "NOT", "children": ["G1"]},
        ],
    }
    with pytest.raises(UserError, match="EXPECTED:CIRCUIT_CYCLE_DETECTED"):
        c.create_circuit("CYC-2", BENEFICIARY, u256(100), json.dumps(self_cycle))


def test_reject_unreachable_orphan_atom_or_gate(env):
    c = KleeneGate(["raw.githubusercontent.com"])
    env.set_caller(SPONSOR, value=100)
    spec = _minimal_valid_spec()
    spec["atoms"].append(
        {"id": "A_ORPHAN", "evidence_url": _gh("f3"), "claim": "Unused orphan claim text."}
    )
    with pytest.raises(UserError, match="EXPECTED:UNREACHABLE_CIRCUIT_NODE"):
        c.create_circuit("ORPH-1", BENEFICIARY, u256(100), json.dumps(spec))


def test_reject_duplicate_gate_child_and_duplicate_atom_pair(env):
    c = KleeneGate(["raw.githubusercontent.com"])
    env.set_caller(SPONSOR, value=100)

    # Duplicate child inside K_OF_N(2; [A1, A1]) gaming attempt
    dup_child = {
        "root_gate_id": "G_ROOT",
        "atoms": [
            {"id": "A1", "evidence_url": _gh("f1"), "claim": "Claim one is verifiable."},
            {"id": "A2", "evidence_url": _gh("f2"), "claim": "Claim two is verifiable."},
        ],
        "gates": [
            {"id": "G_ROOT", "op": "K_OF_N", "k": 2, "children": ["A1", "A1", "A2"]},
        ],
    }
    with pytest.raises(UserError, match="EXPECTED:DUPLICATE_GATE_CHILD"):
        c.create_circuit("DUP-CH", BENEFICIARY, u256(100), json.dumps(dup_child))

    # Sybil attempt: two different atom IDs pointing to exact same URL + claim
    dup_pair = {
        "root_gate_id": "G_ROOT",
        "atoms": [
            {"id": "A1", "evidence_url": _gh("same"), "claim": "Identical claim repeated twice."},
            {"id": "A2", "evidence_url": _gh("same"), "claim": "Identical   claim  repeated twice."},
        ],
        "gates": [
            {"id": "G_ROOT", "op": "AND", "children": ["A1", "A2"]},
        ],
    }
    with pytest.raises(UserError, match="EXPECTED:DUPLICATE_ATOM_PAIR"):
        c.create_circuit("DUP-PAIR", BENEFICIARY, u256(100), json.dumps(dup_pair))


def test_reject_unpinned_github_branch_and_rogue_domain(env):
    c = KleeneGate(["raw.githubusercontent.com"])
    env.set_caller(SPONSOR, value=100)

    # Mutable main branch rejected
    spec_main = _minimal_valid_spec()
    spec_main["atoms"][0]["evidence_url"] = (
        "https://raw.githubusercontent.com/khezzed/Kleene-Gate/main/fixtures/evidence/f1.json"
    )
    with pytest.raises(UserError, match="EXPECTED:UNPINNED_GITHUB_URL"):
        c.create_circuit("UNPIN-1", BENEFICIARY, u256(100), json.dumps(spec_main))

    # 39-hex short SHA rejected
    spec_short = _minimal_valid_spec()
    spec_short["atoms"][0]["evidence_url"] = (
        f"https://raw.githubusercontent.com/khezzed/Kleene-Gate/{'a' * 39}/fixtures/f1.json"
    )
    with pytest.raises(UserError, match="EXPECTED:UNPINNED_GITHUB_URL"):
        c.create_circuit("UNPIN-2", BENEFICIARY, u256(100), json.dumps(spec_short))

    # Unauthorized host rejected
    spec_rogue = _minimal_valid_spec()
    spec_rogue["atoms"][0]["evidence_url"] = "https://evil-oracle.example.com/fake.json"
    with pytest.raises(UserError, match="EXPECTED:DOMAIN_NOT_ALLOWED"):
        c.create_circuit("ROGUE-1", BENEFICIARY, u256(100), json.dumps(spec_rogue))

    # Non-HTTPS rejected
    spec_http = _minimal_valid_spec()
    spec_http["atoms"][0]["evidence_url"] = _gh("f1").replace("https://", "http://")
    with pytest.raises(UserError, match="EXPECTED:HTTPS_REQUIRED"):
        c.create_circuit("HTTP-1", BENEFICIARY, u256(100), json.dumps(spec_http))


def test_reject_invalid_arities_thresholds_and_excessive_depth(env):
    c = KleeneGate(["raw.githubusercontent.com"])
    env.set_caller(SPONSOR, value=100)

    # NOT with 2 children
    bad_not = {
        "root_gate_id": "G_ROOT",
        "atoms": [
            {"id": "A1", "evidence_url": _gh("f1"), "claim": "Claim one is verifiable."},
            {"id": "A2", "evidence_url": _gh("f2"), "claim": "Claim two is verifiable."},
        ],
        "gates": [{"id": "G_ROOT", "op": "NOT", "children": ["A1", "A2"]}],
    }
    with pytest.raises(UserError, match="EXPECTED:INVALID_NOT_ARITY"):
        c.create_circuit("BAD-NOT", BENEFICIARY, u256(100), json.dumps(bad_not))

    # K_OF_N with k > n
    bad_k = {
        "root_gate_id": "G_ROOT",
        "atoms": [
            {"id": "A1", "evidence_url": _gh("f1"), "claim": "Claim one is verifiable."},
            {"id": "A2", "evidence_url": _gh("f2"), "claim": "Claim two is verifiable."},
        ],
        "gates": [{"id": "G_ROOT", "op": "K_OF_N", "k": 3, "children": ["A1", "A2"]}],
    }
    with pytest.raises(UserError, match="EXPECTED:INVALID_GATE_THRESHOLD"):
        c.create_circuit("BAD-K", BENEFICIARY, u256(100), json.dumps(bad_k))

    # Depth 7 chain exceeds MAX_CIRCUIT_DEPTH (6): G7->G6->G5->G4->G3->G2->G1->(A1, A2)
    deep_spec = {
        "root_gate_id": "G7",
        "atoms": [
            {"id": "A1", "evidence_url": _gh("f1"), "claim": "Claim one is verifiable."},
            {"id": "A2", "evidence_url": _gh("f2"), "claim": "Claim two is verifiable."},
        ],
        "gates": [
            {"id": "G1", "op": "AND", "children": ["A1", "A2"]},
            {"id": "G2", "op": "NOT", "children": ["G1"]},
            {"id": "G3", "op": "NOT", "children": ["G2"]},
            {"id": "G4", "op": "NOT", "children": ["G3"]},
            {"id": "G5", "op": "NOT", "children": ["G4"]},
            {"id": "G6", "op": "NOT", "children": ["G5"]},
            {"id": "G7", "op": "NOT", "children": ["G6"]},
        ],
    }
    with pytest.raises(UserError, match="EXPECTED:CIRCUIT_TOO_DEEP"):
        c.create_circuit("DEEP-1", BENEFICIARY, u256(100), json.dumps(deep_spec))


def test_reject_duplicate_circuit_zero_escrow_same_party_and_bad_duration(env):
    c = KleeneGate(["raw.githubusercontent.com"])
    spec_str = json.dumps(_minimal_valid_spec())

    env.set_caller(SPONSOR, value=0)
    with pytest.raises(UserError, match="EXPECTED:ZERO_ESCROW"):
        c.create_circuit("C0", BENEFICIARY, u256(100), spec_str)

    env.set_caller(SPONSOR, value=100)
    with pytest.raises(UserError, match="EXPECTED:SPONSOR_EQUALS_BENEFICIARY"):
        c.create_circuit("C0", SPONSOR, u256(100), spec_str)

    with pytest.raises(UserError, match="EXPECTED:INVALID_DURATION"):
        c.create_circuit("C0", BENEFICIARY, u256(5), spec_str)

    c.create_circuit("C1", BENEFICIARY, u256(100), spec_str)
    with pytest.raises(UserError, match="EXPECTED:DUPLICATE_CIRCUIT_ID"):
        c.create_circuit("C1", BENEFICIARY, u256(100), spec_str)
