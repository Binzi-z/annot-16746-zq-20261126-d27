"""小图水位穷举、名单历史与当前可见权限评估。"""

from __future__ import annotations

from typing import Any

from . import synthetic as S
from .certgraph import ChainInfo
from .engine import decide


def _chain_brief(chains: list[ChainInfo]) -> list[dict[str, Any]]:
    return [c.to_report() for c in chains]


def evaluate_small_graph(kr, seal_digest: str) -> dict[str, Any]:
    events = S.small_graph_events(kr, seal_digest)
    rows: list[dict[str, Any]] = []
    for w in range(len(events) + 1):
        d = decide(
            events, w, "AP-SMALL", S.AT, kr, S.TRUSTED_ROOTS, seal_digest
        )
        row = d.to_row()
        # 附加该水位新出现的事件，便于报告解释
        if w == 0:
            row["new_event"] = "（空水位）"
        else:
            ev = events[w - 1]
            p = ev["envelope"]["payload"]
            row["new_event"] = _describe_event(ev["kind"], p)
        if d.proof is not None:
            row["collapse_notes"] = d.proof.collapse_notes()
            row["shortest_by_root"] = {
                r: c.to_report()
                for r, c in d.proof.shortest_by_root.items()
            }
        else:
            row["collapse_notes"] = []
            row["shortest_by_root"] = {}
        rows.append(row)

    final = decide(
        events, len(events), "AP-SMALL", S.AT, kr, S.TRUSTED_ROOTS, seal_digest
    )
    # w=8 是唯一 OK 水位（撤回在 w=9）
    ok_rows = [r["watermark"] for r in rows if r["allowed"]]
    return {
        "approval_id": "AP-SMALL",
        "decision_instant": S.AT,
        "total_events": len(events),
        "watermarks": rows,
        "ok_watermarks": ok_rows,
        "final_code": final.code,
        "final_allowed": final.allowed,
        "shortest_proof_at_peak": _peak_proof(events, kr, seal_digest),
    }


def _peak_proof(events, kr, seal_digest) -> dict[str, Any]:
    """w=8（撤回前最后一个水位）的最短独立证书。"""
    d = decide(events, 8, "AP-SMALL", S.AT, kr, S.TRUSTED_ROOTS, seal_digest)
    if d.proof is None:
        return {}
    return d.proof.to_report()


def _describe_event(kind: str, p: dict[str, Any]) -> str:
    if kind == "approval":
        return f"批准 {p['approval_id']}（签署人 {p['issuer']}，绑定摘要 {p['seal_digest'][:12]}…）"
    if kind == "cert":
        return f"证书 {p['cert_id']}：{p['issuer']} → {p['subject']}"
    if kind == "revocation":
        return f"撤回 {p['revocation_id']}：{p['issuer']} 撤回 {p['target']}"
    return kind


def evaluate_roster(kr, seal_digest: str) -> dict[str, Any]:
    world = S.build_roster_world(kr, seal_digest)
    events = world["events"]
    blocks = world["blocks"]

    principals: list[dict[str, Any]] = []
    current_visible: list[dict[str, Any]] = []

    for b in blocks:
        block_events = events[b["start"]:b["end"]]
        history: list[dict[str, Any]] = []
        for w in range(len(block_events) + 1):
            d = decide(
                block_events, w, b["approval_id"], S.AT, kr,
                S.TRUSTED_ROOTS, seal_digest,
            )
            history.append(
                {
                    "local_watermark": w,
                    "global_watermark": b["start"] + w,
                    "allowed": d.allowed,
                    "code": d.code,
                    "independent_roots": d.proof.root_votes if d.proof else 0,
                    "eligible_chains": (
                        len(d.proof.eligible) if d.proof else 0
                    ),
                }
            )

        final_d = decide(
            block_events, len(block_events), b["approval_id"], S.AT, kr,
            S.TRUSTED_ROOTS, seal_digest,
        )
        visible_wms = [h["local_watermark"] for h in history if h["allowed"]]
        first_visible = visible_wms[0] if visible_wms else None
        item: dict[str, Any] = {
            "key": b["key"],
            "agent_id": b["agent"],
            "mode": b["mode"],
            "approval_id": b["approval_id"],
            "org": b["org"],
            "resource": b["resource"],
            "block_start_global_wm": b["start"],
            "history": history,
            "visible_local_watermarks": visible_wms,
            "ever_visible": bool(visible_wms),
            "first_visible_local_wm": first_visible,
            "current_allowed": final_d.allowed,
            "current_code": final_d.code,
            "current_reason": final_d.reason_cn,
        }
        if final_d.proof is not None:
            item["independent_roots"] = final_d.proof.independent_roots
            item["root_votes"] = final_d.proof.root_votes
            item["collapse_notes"] = final_d.proof.collapse_notes()
            item["shortest_by_root"] = {
                r: c.to_report()
                for r, c in final_d.proof.shortest_by_root.items()
            }
            item["shortest_independent_certificates"] = [
                c.to_report() for c in final_d.proof.shortest_proof
            ]
        else:
            item["independent_roots"] = []
            item["root_votes"] = 0
            item["collapse_notes"] = []
            item["shortest_by_root"] = {}
            item["shortest_independent_certificates"] = []

        principals.append(item)
        if final_d.allowed:
            current_visible.append(
                {
                    "agent_id": b["agent"],
                    "approval_id": b["approval_id"],
                    "org": b["org"],
                    "resource": b["resource"],
                    "shortest_independent_certificates": item[
                        "shortest_independent_certificates"
                    ],
                    "collapse_notes": item["collapse_notes"],
                }
            )

    # 历史可见权限：曾经出现过 OK 的主体及其可见水位区间
    historical = [
        {
            "agent_id": p["agent_id"],
            "approval_id": p["approval_id"],
            "ever_visible": p["ever_visible"],
            "visible_local_watermarks": p["visible_local_watermarks"],
            "first_visible_local_wm": p["first_visible_local_wm"],
            "currently_visible": p["current_allowed"],
            "current_code": p["current_code"],
        }
        for p in principals
    ]

    return {
        "decision_instant": S.AT,
        "total_world_events": len(events),
        "principals": principals,
        "historical_visibility": historical,
        "current_visible_permissions": current_visible,
        "current_visible_count": len(current_visible),
    }
