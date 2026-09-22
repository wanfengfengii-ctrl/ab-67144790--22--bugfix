"""Deep-chain regression: a legitimate 22-certificate chain (leaf + 20
intermediate CAs + self-signed trust anchor, 21 edges) must be accepted with
the complete path; rejection proofs must cover every reachable branch even
when the reachable region is deeper than any fixed search depth."""
import hashlib
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from tests import pki_factory as pf
from tests.test_e2e import Harness, SIGNED, ANY
from app.certmodel import fp_of


def _build_deep(h, n_intermediates):
    """Returns (keys, chain_certs, leaf) where chain_certs is root-first."""
    keys = [pf.gen_key() for _ in range(n_intermediates + 2)]
    root = pf.build_cert("Deep Root", None, keys[0], keys[0], is_ca=True,
                         key_usage=("keyCertSign", "cRLSign"), policies=[ANY],
                         self_signed=True)
    chain = [root]
    parent = root
    for i in range(n_intermediates):
        c = pf.build_cert(f"Deep CA {i:02d}", parent, keys[i + 1], keys[i],
                          is_ca=True, key_usage=("keyCertSign", "cRLSign"),
                          policies=[ANY])
        chain.append(c)
        parent = c
    leaf = pf.build_cert("deep.leaf.test", parent, keys[-1],
                         keys[n_intermediates],
                         key_usage=("digitalSignature",),
                         eku=("codeSigning",), policies=[ANY],
                         san_dns=("deep.leaf.test",))
    for c in chain + [leaf]:
        h.add_cert(c)
    # One empty (GOOD) CRL per issuer covers leaf + all intermediates.
    for i, issuer in enumerate(chain):
        crl = pf.build_crl(issuer, keys[i], [], last_update=SIGNED - 100,
                           next_update=SIGNED + 100, crl_number=1)
        h.add_rev(crl, i)
    return keys, chain, leaf


def test_deep_chain_22_accepted_with_complete_path(tmp_path):
    h = Harness(tmp_path)
    keys, chain, leaf = _build_deep(h, 20)
    h.seal()
    res = h.judge(leaf, fp_of(pf.der(chain[0])), keys[-1])
    assert res["verdict"]["status"] == "VALID", res["verdict"]
    expected = [fp_of(pf.der(c)) for c in [leaf] + list(reversed(chain))]
    assert res["verdict"]["selected_path"] == expected
    assert len(res["verdict"]["selected_path"]) == 22


def test_deep_chain_beyond_22_still_accepted(tmp_path):
    """No hidden depth ceiling: a 42-certificate chain resolves too."""
    h = Harness(tmp_path)
    keys, chain, leaf = _build_deep(h, 40)
    h.seal()
    res = h.judge(leaf, fp_of(pf.der(chain[0])), keys[-1])
    assert res["verdict"]["status"] == "VALID", res["verdict"]
    expected = [fp_of(pf.der(c)) for c in [leaf] + list(reversed(chain))]
    assert res["verdict"]["selected_path"] == expected


def test_deep_rejection_proof_covers_every_reachable_edge(tmp_path):
    """Chain reaches a root that is not a trust anchor: NO_PATH_TO_ANCHOR is
    correct, and the proof must include all 21 chain edges (not a truncated
    exploration)."""
    h = Harness(tmp_path)
    keys, chain, leaf = _build_deep(h, 20)
    stranger = pf.build_cert("Stranger Anchor", None, keys[-1], keys[-1],
                             is_ca=True, key_usage=("keyCertSign", "cRLSign"),
                             policies=[ANY], self_signed=True)
    h.add_cert(stranger)
    h.seal()
    res = h.judge(leaf, fp_of(pf.der(stranger)), keys[-1])
    assert res["verdict"]["status"] == "REJECTED"
    assert res["verdict"]["failed_rule"] == "NO_PATH_TO_ANCHOR"
    proof = res["verdict"]["rejection_proof"]
    edges = {(e["child"], e["parent"]): e["first_failure"]
             for e in proof["edges"]}
    fps = [fp_of(pf.der(c)) for c in [leaf] + list(reversed(chain))]
    for i in range(len(fps) - 1):
        assert (fps[i], fps[i + 1]) in edges, f"edge {i} missing from proof"
    # The intrinsically valid top edge leads nowhere: annotated accordingly.
    assert edges[(fps[-2], fps[-1])]["rule"] == "NO_PATH_TO_ANCHOR"


def test_deep_chain_revocation_at_depth_still_rejects(tmp_path):
    """A revocation 15 levels down a 22-cert chain is still honoured (the
    search must not skip revocation on deep complete paths)."""
    h = Harness(tmp_path)
    n = 20
    keys, chain, leaf = _build_deep(h, n)
    # Revoke the intermediate issued by the root (deepest non-anchor cert).
    victim = chain[1]
    crl = pf.build_crl(chain[0], keys[0],
                       [(victim.serial_number, SIGNED - 1000,
                         "key_compromise")],
                       last_update=SIGNED - 100, next_update=SIGNED + 100,
                       crl_number=2)
    h.add_rev(crl, 99)
    h.seal()
    res = h.judge(leaf, fp_of(pf.der(chain[0])), keys[-1])
    assert res["verdict"]["status"] == "REJECTED"
    assert res["verdict"]["failed_rule"] == "REVOCATION"


def test_lexicographic_tiebreak_among_equal_length_paths(tmp_path):
    """Two equal-length valid paths to one anchor: the leaf->root fingerprint
    sequence that is lexicographically smallest must win."""
    h = Harness(tmp_path)
    rk, k1, k2, lk = (pf.gen_key() for _ in range(4))
    root = pf.build_cert("Tie Root", None, rk, rk, is_ca=True,
                         key_usage=("keyCertSign", "cRLSign"), policies=[ANY],
                         self_signed=True)
    ca1 = pf.build_cert("Tie CA", root, k1, rk, is_ca=True,
                        key_usage=("keyCertSign", "cRLSign"), policies=[ANY])
    ca2 = pf.build_cert("Tie CA", root, k2, rk, is_ca=True,
                        key_usage=("keyCertSign", "cRLSign"), policies=[ANY])
    leaf = pf.build_cert("tie.leaf", ca1, lk, k1,
                         key_usage=("digitalSignature",),
                         eku=("codeSigning",), policies=[ANY])
    # Second certificate for the same leaf key/name under the twin CA.
    leaf2 = pf.build_cert("tie.leaf", ca2, lk, k2,
                          key_usage=("digitalSignature",),
                          eku=("codeSigning",), policies=[ANY])
    for c in (root, ca1, ca2, leaf, leaf2):
        h.add_cert(c)
    for i, (issuer, key) in enumerate(((root, rk), (ca1, k1), (ca2, k2))):
        crl = pf.build_crl(issuer, key, [], last_update=SIGNED - 100,
                           next_update=SIGNED + 100, crl_number=1)
        h.add_rev(crl, i)
    h.seal()
    res = h.judge(leaf, fp_of(pf.der(root)), lk)
    assert res["verdict"]["status"] == "VALID", res["verdict"]
    fps = sorted([fp_of(pf.der(ca1)), fp_of(pf.der(ca2))])
    expected = [fp_of(pf.der(leaf)), fps[0], fp_of(pf.der(root))]
    assert res["verdict"]["selected_path"] == expected
