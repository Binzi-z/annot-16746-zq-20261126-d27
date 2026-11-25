import tempfile
import pathlib

from dutyauth import synthetic as S
from dutyauth.seal import compute_seal_digest
from dutyauth.engine import decide
from dutyauth.concurrency import run_all_concurrency

kr = S.make_keyring()
sd = compute_seal_digest("sealed_workspace")
print("seal digest:", sd[:16], "...")

ev = S.small_graph_events(kr, sd)
print("small graph events:", len(ev))
for w in range(len(ev) + 1):
    d = decide(ev, w, "AP-SMALL", S.AT, kr, S.TRUSTED_ROOTS, sd)
    roots = d.proof.root_votes if d.proof else 0
    chains = len(d.proof.eligible) if d.proof else 0
    print(f"w={w:2d} allowed={str(d.allowed):5} code={d.code:22} roots={roots} chains={chains}")

with tempfile.TemporaryDirectory() as td:
    rep = run_all_concurrency(pathlib.Path(td), kr, sd)
    print("concurrency all invariants:", rep["all_invariants_hold"])
    a = rep["revocation_order"]
    b = rep["persisted_ack_lost"]
    c = rep["same_seq_diff_digest"]
    print("A:", a["invariants_hold"])
    print("  revoke-first visible:", a["revoke_first"]["ever_visible"], a["revoke_first"]["commit_indices"])
    print("  contrast visible watermarks:", a["approve_first_contrast"]["visible_watermarks"])
    print("B:", b["invariants_hold"], "same_index:", b["same_index"], "decision:", b["final_decision_code"])
    print("C:", c["invariants_hold"], "approvals:", c["approval_records"], "evidence:", c["equivocation_evidence_records"], "decision:", c["final_decision_code"])
