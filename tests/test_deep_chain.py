"""Deep-chain regression: long legitimate chains must be accepted, and
NO_PATH_TO_ANCHOR may only be returned after the reachable candidate space
is truly exhausted, with a rejection proof covering every reachable branch.

A chain of 22 certificates (leaf + 20 intermediate CAs + trust anchor, 21
edges) exceeds the historical exploration horizon; these tests pin the
complete-search behavior on both the accept and the reject side.
"""
import hashlib
import os
import sys

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from tests import pki_factory as pf
from app.storage import Store
from app.adjudge import adjudicate
from app.package import build_package
from app.certmodel import fp_of
from verify.verify_package import verify_package

ANY = "2.5.29.32.0"
SIGNED = 1_700_000_000
CUTOFF = 1_701_000_000
RECEIVED = 1_699_000_000


class DeepHarness:
    def __init__(self, tmp_path, n_ca):
        self.store = Store(str(tmp_path / "data"))
        self.sid = f"es_deep_{n_ca:020d}"[:32]
        self.store.create_set(self.sid, "c")
        self.rows = []
        self.n_ca = n_ca
        # keys[0] -> root, keys[1..n_ca] -> intermediates, keys[-1] -> leaf
        self.keys = [pf.gen_key() for _ in range(n_ca + 2)]
        self.root = pf.build_cert(
            "Deep Root", None, self.keys[0], self.keys[0], is_ca=True,
            key_usage=("keyCertSign", "cRLSign"), policies=[ANY],
            self_signed=True)
        self.chain = [self.root]  # root -> CA-01 -> ... -> CA-n_ca
        for i in range(1, n_ca + 1):
            self.chain.append(pf.build_cert(
                f"CA-{i:02d}", self.chain[-1], self.keys[i], self.keys[i - 1],
                is_ca=True, key_usage=("keyCertSign", "cRLSign"),
                policies=[ANY]))
        self.leaf = pf.build_cert(
            "deep.leaf", self.chain[-1], self.keys[-1], self.keys[n_ca],
            key_usage=("digitalSignature",), eku=("codeSigning",),
            policies=[ANY], san_dns=("deep.leaf",))

    def add_cert(self, c):
        d = pf.der(c)
        self.store.put_blob(d)
        self.rows.append({"client_ref": "c" + fp_of(d)[:16],
                          "kind": "certificate", "content_sha256": fp_of(d),
                          "received_at": RECEIVED})

    def add_crl(self, c, idx):
        d = pf.der(c)
        self.store.put_blob(d)
        self.rows.append({"client_ref": f"r{idx}", "kind": "crl",
                          "content_sha256": fp_of(d),
                          "received_at": RECEIVED})

    def good_crls(self, revoked=()):
        """One in-window CRL per issuer; every non-anchor cert is GOOD
        unless its serial is listed in ``revoked``."""
        revoked = dict(revoked)
        crls = []
        for i, issuer in enumerate(self.chain):
            entries = []
            child = self.chain[i + 1] if i + 1 < len(self.chain) else self.leaf
            if fp_of(pf.der(child)) in revoked:
                entries.append((child.serial_number, SIGNED - 1_000,
                                "key_compromise"))
            crls.append(pf.build_crl(issuer, self.keys[i], entries,
                                     last_update=SIGNED - 100,
                                     next_update=SIGNED + 100, crl_number=1))
        return crls

    def seal(self):
        self.store.add_items(self.sid, self.rows)
        return self.store.seal(self.sid)

    def judge(self, anchor_fp):
        d = hashlib.sha256(b"deep-artifact").digest()
        s = self.keys[-1].sign(d, ec.ECDSA(Prehashed(hashes.SHA256())))
        return adjudicate(self.store, self.sid, {
            "artifact_digest": d.hex(), "signature": s.hex(),
            "signature_algorithm": "1.2.840.10045.4.3.2",
            "signed_at": SIGNED, "knowledge_cutoff": CUTOFF,
            "leaf_certificate_sha256": fp_of(pf.der(self.leaf)),
            "initial_policies": [ANY], "trust_anchors": [anchor_fp]})

    def expected_path(self):
        return [fp_of(pf.der(c))
                for c in [self.leaf] + list(reversed(self.chain))]


def _build(h, tmp_path, n_ca, extra_certs=(), revoked=()):
    for c in list(h.chain) + [h.leaf] + list(extra_certs):
        h.add_cert(c)
    for i, crl in enumerate(h.good_crls(revoked)):
        h.add_crl(crl, i)
    return h.seal()


def test_deep_chain_22_accepted_full_path(tmp_path):
    """The 22-certificate scenario: 1 leaf + 20 CAs + 1 anchor, 21 edges."""
    h = DeepHarness(tmp_path, n_ca=20)
    manifest = _build(h, tmp_path, 20)
    res = h.judge(fp_of(pf.der(h.root)))
    assert res["verdict"]["status"] == "VALID", res["verdict"]
    path = res["verdict"]["selected_path"]
    assert path == h.expected_path()
    assert len(path) == 22
    # Every non-anchor cert on the path was revocation-checked GOOD.
    assert len(res["revocation_results"]) == 21
    assert all(r["conclusion"] == "GOOD" for r in res["revocation_results"])
    assert len(res["policy_trace"]) == 22
    # The evidence package must re-verify offline byte-for-byte.
    pkg = build_package(h.store, res, manifest)
    pkg_path = tmp_path / "deep22.zip"
    pkg_path.write_bytes(pkg)
    report = verify_package(str(pkg_path))
    assert report["ok"], [c for c in report["checks"] if not c["ok"]]


def test_chain_beyond_22_also_accepted(tmp_path):
    """No new hidden ceiling just above 22: a 30-certificate chain works."""
    h = DeepHarness(tmp_path, n_ca=28)
    _build(h, tmp_path, 28)
    res = h.judge(fp_of(pf.der(h.root)))
    assert res["verdict"]["status"] == "VALID", res["verdict"]
    assert res["verdict"]["selected_path"] == h.expected_path()
    assert len(res["verdict"]["selected_path"]) == 30


def test_deep_chain_revoked_intermediate_reports_full_path(tmp_path):
    """A revocation deep in a 22-cert chain rejects with REVOCATION, and the
    evaluated complete (22-cert) candidate path appears in the proof."""
    h = DeepHarness(tmp_path, n_ca=20)
    victim = h.chain[10]  # CA-10, mid-chain
    _build(h, tmp_path, 20,
           revoked=[(fp_of(pf.der(victim)), "key_compromise")])
    res = h.judge(fp_of(pf.der(h.root)))
    assert res["verdict"]["status"] == "REJECTED"
    assert res["verdict"]["failed_rule"] == "REVOCATION"
    proof = res["verdict"]["rejection_proof"]
    plf = proof["path_level_failures"]
    assert len(plf) == 1
    assert plf[0]["rule"] == "REVOCATION"
    assert plf[0]["at"] == fp_of(pf.der(victim))
    assert plf[0]["example_path"] == h.expected_path()


def test_deep_chain_no_path_to_anchor_proof_covers_all_branches(tmp_path):
    """Anchor unreachable from a 22-cert chain: rejection is allowed only
    after exhaustion, and the proof must cover every reachable edge."""
    h = DeepHarness(tmp_path, n_ca=20)
    other_key = pf.gen_key()
    other_root = pf.build_cert("Other Root", None, other_key, other_key,
                               is_ca=True, key_usage=("keyCertSign", "cRLSign"),
                               policies=[ANY], self_signed=True)
    manifest = _build(h, tmp_path, 20, extra_certs=[other_root])
    res = h.judge(fp_of(pf.der(other_root)))
    assert res["verdict"]["status"] == "REJECTED"
    assert res["verdict"]["failed_rule"] == "NO_PATH_TO_ANCHOR"
    proof = res["verdict"]["rejection_proof"]
    assert proof is not None
    edges = {(e["child"], e["parent"]): e["first_failure"]
             for e in proof["edges"]}
    # All 21 chain edges were explored (nothing truncated) ...
    fps = [fp_of(pf.der(c)) for c in [h.leaf] + list(reversed(h.chain))]
    for child, parent in zip(fps, fps[1:]):
        assert (child, parent) in edges, (child, parent)
        assert edges[(child, parent)]["rule"] == "NO_PATH_TO_ANCHOR"
    # ... including the chain root's self-loop frontier.
    root_fp = fp_of(pf.der(h.root))
    assert edges[(root_fp, root_fp)]["rule"] == "LOOP"
    # No anchor-terminated candidate path exists, so no path-level failure.
    assert proof["path_level_failures"] == []
    # The rejection package still re-verifies offline byte-for-byte.
    pkg = build_package(h.store, res, manifest)
    pkg_path = tmp_path / "deep22_rejected.zip"
    pkg_path.write_bytes(pkg)
    report = verify_package(str(pkg_path))
    assert report["ok"], [c for c in report["checks"] if not c["ok"]]
