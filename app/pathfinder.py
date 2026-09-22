"""Whole-graph path construction with deterministic selection and a
complete rejection proof.

Search is best-first over simple paths, ordered by (certificate count,
leaf->root fingerprint sequence): exactly the iterative-deepening order,
but with no artificial depth cap. The first chain that passes *every* gate
(signature, validity, hierarchy, pathLen, name constraints, policy, EKU,
bitemporal revocation) in that order is the unique required winner (fewest
certs, lexicographically smallest leaf->root fingerprint sequence).
Revocation is checked on every complete anchor path, never after fixing one
shortest chain.

Exploration is lazy: from a certificate only name/AKI-compatible issuers are
considered, so 100k unrelated certificates add essentially zero work. Cycles
are blocked with the on-path set, so every candidate path is finite and the
search terminates on cyclic and cross-signed graphs; NO_PATH_TO_ANCHOR is
reported only after the reachable candidate space is truly exhausted, and
the rejection proof covers every reachable branch. All edge and node
results are memoized.
"""
from __future__ import annotations

import heapq

from .chain import (
    check_eku,
    check_name_constraints,
    check_path_len,
    process_policies,
)
from .graph import CertGraph


class PathFinder:
    def __init__(self, graph: CertGraph, anchors: set[str], revocation_eval,
                 signed_at: int, initial_policies: frozenset[str]):
        self.g = graph
        self.anchors = anchors
        self.rev = revocation_eval
        self.signed_at = signed_at
        self.initial_policies = initial_policies
        self.edge_failures: dict[tuple[str, str], dict] = {}
        self.node_failures: dict[str, dict] = {}
        self.path_outcomes: list[dict] = []
        self.edges_seen: set[tuple[str, str]] = set()
        self._last_good: dict | None = None
        self._intrinsic_cache: dict[tuple[str, bool], dict | None] = {}
        self._parents_cache: dict[str, list[str]] = {}

    # --------------------------------------------------------------- nodes
    def _node_intrinsic(self, fp: str, as_issuer: bool) -> dict | None:
        key = (fp, as_issuer)
        if key in self._intrinsic_cache:
            return self._intrinsic_cache[key]
        pc = self.g.get_cert(fp)
        failure = None
        if not (pc.not_before <= self.signed_at <= pc.not_after):
            failure = {"rule": "VALIDITY",
                       "detail": {"not_before": pc.not_before,
                                  "not_after": pc.not_after,
                                  "signed_at": self.signed_at}}
        elif as_issuer:
            if not pc.is_ca:
                failure = {"rule": "BASIC_CONSTRAINTS",
                           "detail": {"reason": "issuer certificate is not a CA"}}
            elif pc.key_usage and "keyCertSign" not in pc.key_usage:
                failure = {"rule": "KEY_USAGE",
                           "detail": {"reason": "issuer lacks keyCertSign"}}
        self._intrinsic_cache[key] = failure
        return failure

    def _revocation_gate(self, fps: list[str]) -> tuple[dict | None, dict]:
        details = {}
        # Trust anchor revocation status is not evaluated (RFC 5280 §6.1.3).
        for fp in fps[:-1]:
            res = self.rev(self.g.get_cert(fp))
            details[fp] = {"conclusion": res["conclusion"],
                           "selected_evidence": res["selected_evidence"]}
            if res["conclusion"] != "GOOD":
                return {"rule": "REVOCATION",
                        "at": fp,
                        "conclusion": res["conclusion"]}, details
        return None, details

    # ----------------------------------------------------------------- API
    def find(self, leaf_fp: str) -> dict:
        self._intrinsic_cache: dict[tuple[str, bool], dict | None] = {}
        self._parents_cache: dict[str, list[str]] = {}
        if self.g.get_cert(leaf_fp) is None:
            return {"status": "REJECTED",
                    "reason": {"rule": "LEAF_NOT_IN_EVIDENCE_SET"},
                    "selected_path": None, "rejection_proof": None}
        lf = self._node_intrinsic(leaf_fp, as_issuer=False)
        if lf is not None:
            return self._reject(leaf_fp, lf)
        if leaf_fp in self.anchors:
            return {"status": "ACCEPTED", "reason": None,
                    "selected_path": [leaf_fp],
                    "policy_trace": [], "revocation": {},
                    "rejection_proof": None}

        self._last_good = None
        self._search(leaf_fp)
        winner = self._last_good
        if winner is not None:
            return {"status": "ACCEPTED", "reason": None,
                    "selected_path": winner["path"],
                    "policy_trace": winner["policy_trace"],
                    "revocation": winner["revocation"],
                    "rejection_proof": None,
                    "explored_edges": sorted(self.edges_seen),
                    "node_failures": [
                        {"certificate": fp, **f}
                        for (fp, as_issuer), f in self._intrinsic_cache.items()
                        if f is not None]}
        if self.path_outcomes:
            # Complete anchor-terminated paths existed but all failed a
            # whole-path gate; report the failure on the deterministic
            # smallest (length, fingerprint) such path.
            rep = sorted(self.path_outcomes,
                         key=lambda o: (len(o["path"]), o["path"]))[0]
            terminal = {"rule": rep["rule"],
                        "detail": {"at": rep["at"], "anchor": rep["anchor"],
                                   "example_path": rep["path"]}}
        else:
            terminal = self.node_failures.get(leaf_fp) or {"rule": "NO_PATH_TO_ANCHOR"}
        return self._reject(leaf_fp, terminal)

    # -------------------------------------------------------------- search
    def _static_parents(self, fp: str) -> list[str]:
        """Name/key- and signature-valid issuer fingerprints (sorted)."""
        cached = self._parents_cache.get(fp)
        if cached is not None:
            return cached
        out: list[str] = []
        for ip in self.g.candidate_issuers(fp):
            self.edges_seen.add((fp, ip))
            e = self.g.edge(fp, ip)
            if not e.name_key_ok:
                self.edge_failures.setdefault((fp, ip), {"rule": "ISSUER_NAME_KEY"})
            elif not e.sig_ok:
                self.edge_failures.setdefault((fp, ip),
                                              {"rule": e.sig_rule or "SIGNATURE"})
            else:
                out.append(ip)
        out.sort()
        self._parents_cache[fp] = out
        return out

    def _search(self, leaf_fp: str) -> None:
        """Best-first enumeration of simple paths from the leaf in
        (certificate count, fingerprint sequence) order; sets
        ``self._last_good`` on the first complete anchor path that passes
        every gate. Returns only when a winner is found or the reachable
        candidate space is exhausted: the on-path set blocks cycles, so
        every queued path is finite and the frontier eventually empties.
        There is no depth cap beyond the graph itself."""
        frontier: list[tuple[int, tuple[str, ...]]] = [(1, (leaf_fp,))]
        while frontier:
            _, path = heapq.heappop(frontier)
            last = path[-1]
            if last in self.anchors:
                if self._complete_path(path) is None:
                    return
                continue
            on_path = set(path)
            for ip in self._static_parents(last):
                if ip in on_path:
                    self.edge_failures.setdefault((last, ip), {"rule": "LOOP"})
                    continue
                nf = self._node_intrinsic(ip, as_issuer=True)
                if nf is not None:
                    self.edge_failures.setdefault((last, ip), nf)
                    continue
                heapq.heappush(frontier, (len(path) + 1, path + (ip,)))

    def _complete_path(self, path: tuple[str, ...]):
        rev_fail, rev_details = self._revocation_gate(list(path))
        if rev_fail is not None:
            self._record_path_failure(path, rev_fail)
            return rev_fail
        parsed = [self.g.get_cert(f) for f in path]
        for check in (check_path_len, check_name_constraints, check_eku):
            ok, detail = check(parsed)
            if not ok:
                self._record_path_failure(path, detail)
                return detail
        ok, detail, trace = process_policies(parsed, self.initial_policies)
        if not ok:
            self._record_path_failure(path, detail)
            return detail
        self._last_good = {"path": list(path), "policy_trace": trace,
                           "revocation": rev_details}
        return None

    def _record_path_failure(self, path: tuple[str, ...], detail: dict) -> None:
        rule = detail["rule"]
        at = detail.get("at", path[-1])
        self.path_outcomes.append({"path": list(path), "rule": rule,
                                   "at": at, "anchor": path[-1]})
        edge = (path[-2], path[-1])
        self.edge_failures.setdefault(edge, {"rule": rule, "at": at,
                                             "path_level": True})

    # ------------------------------------------------------- rejection proof
    def _reject(self, leaf_fp: str, terminal: dict) -> dict:
        self._annotate_dead_frontiers()
        groups: dict[tuple, dict] = {}
        for o in self.path_outcomes:
            key = (o["anchor"], o["rule"], o["at"])
            g = groups.setdefault(key, {"anchor": o["anchor"], "rule": o["rule"],
                                        "at": o["at"], "path_count": 0,
                                        "example_path": o["path"]})
            g["path_count"] += 1
        edges = [{"child": c, "parent": p,
                  "first_failure": self.edge_failures.get((c, p))}
                 for (c, p) in sorted(self.edges_seen)]
        proof = {
            "leaf": leaf_fp,
            "terminal_failure": terminal,
            "edges": edges,
            "node_failures": [{"certificate": fp, **f}
                              for fp, f in sorted(self.node_failures.items())],
            "path_level_failures": sorted(
                groups.values(),
                key=lambda x: (x["anchor"], x["rule"], x["at"], x["example_path"])),
            "coverage": ("every name/key-compatible issuer edge cryptographically"
                         " considered from the leaf's reachable branch set"),
        }
        return {"status": "REJECTED", "reason": terminal,
                "selected_path": None, "rejection_proof": proof}

    def _annotate_dead_frontiers(self) -> None:
        """Edges intrinsically valid but leading to a branch that can never
        terminate at an anchor get NO_PATH_TO_ANCHOR, so the proof covers all
        reachable candidate branches rather than only the final attempt."""
        # Static adjacency among explored nodes.
        parents_of: dict[str, set[str]] = {}
        for (c, p) in self.edges_seen:
            parents_of.setdefault(c, set()).add(p)
        # Reverse reachability to any anchor over explored edges.
        can: set[str] = set(self.anchors)
        children_of: dict[str, set[str]] = {}
        for c, ps in parents_of.items():
            for p in ps:
                children_of.setdefault(p, set()).add(c)
        stack = list(can)
        seen = set(can)
        while stack:
            p = stack.pop()
            for c in children_of.get(p, ()):  # only explored edges
                if c not in seen:
                    seen.add(c)
                    stack.append(c)
        for (c, p) in self.edges_seen:
            if self.edge_failures.get((c, p)):
                continue
            e = self.g.edge(c, p)
            if e.name_key_ok and e.sig_ok and p not in seen:
                self.edge_failures[(c, p)] = {"rule": "NO_PATH_TO_ANCHOR"}
        # Merge node_failures from cache (issuer-side failures only).
        for (fp, as_issuer), fail in self._intrinsic_cache.items():
            if fail is not None:
                self.node_failures.setdefault(fp, fail)
