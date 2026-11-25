"""给定水位（只看前 w 条事件）与时刻的离线授权判定。

判定检查顺序（任一不满足即拒绝，拒绝码稳定、可测试）：

1. 水位内存在批准记录且签署有效；
2. 该记录序号未卷入“同号异摘要”冲突；
3. 记录绑定的封存摘要 == 工作区实际内容摘要；
4. 当前时刻落在任期内；
5. 批准范围覆盖请求的组织/资源；
6. 不存在有权上游作出的有效撤回；
7. 证书图能溯源到 >=2 个不同控制根（同源多链只算一票）。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .certgraph import Cert, CertGraph, ProofResult
from .canon import Keyring, verify
from .scope import Scope, Term

REASON_CN = {
    "OK": "允许：任期、资源范围、封存摘要均有效，且具备两个独立控制根",
    "NO_APPROVAL": "该水位内找不到指定批准记录",
    "BAD_APPROVAL_SIGNATURE": "批准记录的签署验证失败",
    "EQUIVOCATION": "同一签发序号携带不同内容摘要（equivocation），该序号已冻结",
    "SEAL_MISMATCH": "授权绑定的封存摘要与工作区实际内容摘要不一致",
    "TERM_NOT_STARTED": "任期尚未开始",
    "TERM_EXPIRED": "任期已结束",
    "SCOPE_ORG_MISMATCH": "资源范围的组织不匹配",
    "SCOPE_DENIED": "请求资源超出批准的资源范围",
    "REVOKED": "批准已被有权上游撤回，且撤回先于/并存于当前水位",
    "INSUFFICIENT_ROOTS": "独立控制根不足：同一上游的多条链只算一票",
}


@dataclass
class Decision:
    allowed: bool
    code: str
    reason_cn: str
    watermark: int
    at: int
    approval_id: str
    proof: ProofResult | None = None
    details: dict[str, Any] = field(default_factory=dict)

    def to_row(self) -> dict[str, Any]:
        p = self.proof
        return {
            "watermark": self.watermark,
            "allowed": self.allowed,
            "code": self.code,
            "reason_cn": self.reason_cn,
            "independent_roots": p.root_votes if p else 0,
            "structural_chains": len(p.all_chains) if p else 0,
            "eligible_chains": len(p.eligible) if p else 0,
            "shortest_lengths": (
                {r: c.length for r, c in p.shortest_by_root.items()} if p else {}
            ),
        }


def _envelope_of(event: dict[str, Any]) -> dict[str, Any] | None:
    env = event.get("envelope")
    return env if isinstance(env, dict) else None


def find_approval(
    events: list[dict[str, Any]], approval_id: str
) -> tuple[dict[str, Any], dict[str, Any]] | None:
    """返回 (event, envelope)。"""
    for ev in events:
        if ev.get("kind") != "approval":
            continue
        env = _envelope_of(ev)
        if env and env.get("payload", {}).get("approval_id") == approval_id:
            return ev, env
    return None


def serial_is_conflicted(
    events: list[dict[str, Any]], issuer: str, serial: Any
) -> dict[str, Any] | None:
    """扫描 equivocation 证据/账本索引事件，返回冲突证据。"""
    for ev in events:
        kind = str(ev.get("kind", ""))
        if not kind.startswith("equivocation"):
            continue
        if ev.get("issuer") == issuer and str(ev.get("serial")) == str(serial):
            return ev
        env = _envelope_of(ev)
        if env:
            p = env.get("payload", {})
            if p.get("typ") == "equivocation" and p.get("issuer") == issuer:
                if str(p.get("serial")) == str(serial):
                    return ev
    return None


def build_graph(
    events: list[dict[str, Any]], keyring: Keyring, trusted_roots: set[str]
) -> tuple[CertGraph, list[dict[str, Any]]]:
    graph = CertGraph(trusted_roots)
    bad: list[dict[str, Any]] = []
    for idx, ev in enumerate(events):
        if ev.get("kind") != "cert":
            continue
        env = _envelope_of(ev)
        if env is None:
            continue
        try:
            graph.add(Cert.from_signed(env, keyring, seq=idx))
        except Exception as exc:  # 验签失败/格式错误的证书不进图
            bad.append({"index": idx, "error": str(exc)})
    return graph, bad


def _authorized_revocation(
    events: list[dict[str, Any]],
    approval_id: str,
    keyring: Keyring,
    graph: CertGraph,
    target_signer: str,
) -> dict[str, Any] | None:
    """找到目标批准的、签署有效且撤回人有上游权力的撤回。"""
    ancestor_issuers: set[str] = set()
    for ch in graph.structural_chains(target_signer):
        for c in ch.certs:
            ancestor_issuers.add(c.issuer)

    for ev in events:
        if ev.get("kind") != "revocation":
            continue
        env = _envelope_of(ev)
        if env is None or not verify(env, keyring):
            continue
        p = env.get("payload", {})
        if p.get("typ") != "revocation" or p.get("target") != approval_id:
            continue
        revoker = env.get("kid") or p.get("issuer")
        if revoker in graph.trusted_roots or revoker in ancestor_issuers:
            return p
    return None


def decide(
    all_events: list[dict[str, Any]],
    watermark: int,
    approval_id: str,
    at: int,
    keyring: Keyring,
    trusted_roots: set[str],
    actual_seal_digest: str,
    required_roots: int = 2,
    resource_override: str | None = None,
) -> Decision:
    """watermark 为可见事件数（前 watermark 条，水位 0 表示空）。"""
    events = all_events[:watermark]

    found = find_approval(events, approval_id)
    if found is None:
        return Decision(
            False, "NO_APPROVAL", REASON_CN["NO_APPROVAL"], watermark, at, approval_id
        )

    _ev, env = found
    payload = env.get("payload", {})
    signer = env.get("kid") or payload.get("issuer")

    # 即使后续拒绝，也尽量给出证书统计
    graph, bad_certs = build_graph(events, keyring, trusted_roots)
    resource = resource_override if resource_override is not None else payload.get(
        "resource", ""
    )
    org = payload.get("org", "")
    proof: ProofResult | None = None
    if signer:
        proof = graph.proof_for(signer, at, org, resource)
        proof.required_roots = required_roots

    def deny(code: str, **details: Any) -> Decision:
        return Decision(
            False,
            code,
            REASON_CN[code],
            watermark,
            at,
            approval_id,
            proof=proof,
            details=details,
        )

    if not verify(env, keyring):
        return deny("BAD_APPROVAL_SIGNATURE", bad_certs=bad_certs)

    conflict = serial_is_conflicted(events, signer, payload.get("serial"))
    if conflict is not None:
        return deny("EQUIVOCATION", evidence=_compact_conflict(conflict))

    if payload.get("seal_digest") != actual_seal_digest:
        return deny(
            "SEAL_MISMATCH",
            bound=payload.get("seal_digest"),
            actual=actual_seal_digest,
        )

    term = Term.from_obj(payload["term"])
    if at < term.not_before:
        return deny("TERM_NOT_STARTED", term=term.to_obj())
    if at >= term.not_after:
        return deny("TERM_EXPIRED", term=term.to_obj())

    scope = Scope.from_obj(payload["scope"])
    if scope.org != org:
        return deny("SCOPE_ORG_MISMATCH", scope_org=scope.org, org=org)
    if not scope.covers_resource(org, resource):
        return deny("SCOPE_DENIED", scope=scope.to_obj(), resource=resource)

    rev = _authorized_revocation(
        events, approval_id, keyring, graph, str(signer)
    )
    if rev is not None:
        return deny("REVOKED", revocation=rev)

    if proof is None or not proof.enough:
        return deny(
            "INSUFFICIENT_ROOTS",
            votes=proof.root_votes if proof else 0,
            required=required_roots,
            collapse=(proof.collapse_notes() if proof else []),
        )

    return Decision(
        True,
        "OK",
        REASON_CN["OK"],
        watermark,
        at,
        approval_id,
        proof=proof,
        details={"collapse": proof.collapse_notes(), "bad_certs": bad_certs},
    )


def _compact_conflict(ev: dict[str, Any]) -> dict[str, Any]:
    if "evidence" in ev:
        return ev["evidence"]
    env = _envelope_of(ev)
    if env:
        return env.get("payload", {})
    return {k: ev.get(k) for k in ("issuer", "serial", "digests", "digest")}
