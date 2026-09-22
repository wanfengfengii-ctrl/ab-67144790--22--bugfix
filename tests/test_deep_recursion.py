"""Recursion-safety: path search uses an explicit stack, so chains far deeper
than the interpreter recursion limit neither crash nor get truncated."""
import os
import sys
import types

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from app.pathfinder import PathFinder

SIGNED = 1_700_000_000


class _StubEdge:
    def __init__(self):
        self.sig_ok = True
        self.sig_rule = None
        self.name_key_ok = True


class _StubGraph:
    """Linear synthetic chain c0 -> c1 -> ... -> cN (no real crypto)."""

    def __init__(self, n):
        self.n = n
        self._edge = _StubEdge()

    def get_cert(self, fp):
        if not isinstance(fp, int) or not (0 <= fp <= self.n):
            return None
        return types.SimpleNamespace(fingerprint=fp, not_before=SIGNED - 10,
                                     not_after=SIGNED + 10, is_ca=fp != 0,
                                     key_usage=("keyCertSign",))

    def candidate_issuers(self, fp):
        return [fp + 1] if fp < self.n else []

    def edge(self, child, issuer):
        return self._edge


def _good_rev(cert):
    return {"conclusion": "GOOD", "selected_evidence": None}


def test_chain_deeper_than_recursion_limit_terminates():
    depth = 1200  # beyond Python's default recursion limit of 1000
    assert depth > sys.getrecursionlimit()
    graph = _StubGraph(depth)
    finder = PathFinder(graph, anchors=set(), revocation_eval=_good_rev,
                        signed_at=SIGNED, initial_policies=frozenset())
    outcome = finder.find(0)
    # No anchor anywhere: full exploration, then NO_PATH_TO_ANCHOR with a
    # proof covering every one of the `depth` edges.
    assert outcome["status"] == "REJECTED"
    assert outcome["reason"]["rule"] == "NO_PATH_TO_ANCHOR"
    proof_edges = {(e["child"], e["parent"])
                   for e in outcome["rejection_proof"]["edges"]}
    assert {(i, i + 1) for i in range(depth)} <= proof_edges


def test_deep_synthetic_chain_to_anchor_accepted():
    depth = 1200
    graph = _StubGraph(depth)
    finder = PathFinder(graph, anchors={depth}, revocation_eval=_good_rev,
                        signed_at=SIGNED, initial_policies=frozenset())

    # Whole-path gates need real certificates; keep only the revocation gate
    # and record the winner exactly like the real _complete_path does.
    def fake_complete(path):
        fail, details = finder._revocation_gate(list(path))
        if fail is not None:
            return fail
        finder._last_good = {"path": list(path), "policy_trace": [],
                             "revocation": details}
        return None

    finder._complete_path = fake_complete
    outcome = finder.find(0)
    assert outcome["status"] == "ACCEPTED"
    assert outcome["selected_path"] == list(range(depth + 1))
