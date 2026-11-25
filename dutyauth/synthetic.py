"""确定性合成数据：签署构造器、小证书图、值班名单世界。

所有时间为合成逻辑秒，判定时刻 AT 固定，保证报告可复现。
"""

from __future__ import annotations

from typing import Any

from .canon import Keyring, sign

# 两个相互独立的控制根
ROOT_DUTY = "root-duty"          # 值班任期控制根
ROOT_RESOURCE = "root-resource"  # 资源范围控制根
TRUSTED_ROOTS = {ROOT_DUTY, ROOT_RESOURCE}

# 小图节点
U = "u-ops"
M1 = "m-lead-1"
M2 = "m-lead-2"
N = "n-res"
LEADER = "leader-lin"

ORG = "east"
AT = 1_760_000_000
TERM_LO = 1_700_000_000
TERM_HI = 1_820_000_000

WRONG_DIGEST = "0" * 64


def make_keyring() -> Keyring:
    # 合成环境下任意 kid 的密钥都可确定性派生；两个根因此持有不同密钥。
    return Keyring()


# ----------------------------------------------------------------------
# 事件构造器
# ----------------------------------------------------------------------
def cert_event(
    kr: Keyring,
    cert_id: str,
    issuer: str,
    subject: str,
    *,
    org: str = ORG,
    patterns: tuple[str, ...] = ("*",),
    lo: int = TERM_LO,
    hi: int = TERM_HI,
) -> dict[str, Any]:
    payload = {
        "typ": "cert",
        "cert_id": cert_id,
        "issuer": issuer,
        "subject": subject,
        "scope": {"org": org, "patterns": list(patterns)},
        "term": {"not_before": lo, "not_after": hi},
    }
    return {"kind": "cert", "envelope": sign(payload, issuer, kr)}


def approval_event(
    kr: Keyring,
    *,
    approval_id: str,
    signer: str,
    serial: str,
    agent_id: str,
    seal_digest: str,
    org: str = ORG,
    patterns: tuple[str, ...] = ("db/prod/",),
    resource: str = "db/prod/primary",
    lo: int = TERM_LO,
    hi: int = TERM_HI,
) -> dict[str, Any]:
    payload = {
        "typ": "approval",
        "approval_id": approval_id,
        "issuer": signer,
        "serial": serial,
        "agent_id": agent_id,
        "org": org,
        "resource": resource,
        "scope": {"org": org, "patterns": list(patterns)},
        "term": {"not_before": lo, "not_after": hi},
        "seal_digest": seal_digest,
    }
    return {"kind": "approval", "envelope": sign(payload, signer, kr)}


def revocation_event(
    kr: Keyring,
    *,
    revocation_id: str,
    target: str,
    issuer: str,
    reason: str = "duty-ended-early",
) -> dict[str, Any]:
    payload = {
        "typ": "revocation",
        "revocation_id": revocation_id,
        "target": target,
        "issuer": issuer,
        "reason": reason,
    }
    return {"kind": "revocation", "envelope": sign(payload, issuer, kr)}


# ----------------------------------------------------------------------
# 小图：菱形同源双链 + 独立第二根
# ----------------------------------------------------------------------
def small_cert_events(kr: Keyring) -> list[dict[str, Any]]:
    """7 张证书，顺序即水位推进顺序。"""
    return [
        cert_event(kr, "C1-root-u", ROOT_DUTY, U, patterns=("*",)),
        cert_event(kr, "C2-u-m1", U, M1, patterns=("db/",)),
        cert_event(kr, "C3-m1-l", M1, LEADER, patterns=("db/prod/",)),
        cert_event(kr, "C4-u-m2", U, M2, patterns=("db/",)),
        cert_event(kr, "C5-m2-l", M2, LEADER, patterns=("db/prod/",)),
        cert_event(kr, "C6-root-n", ROOT_RESOURCE, N, patterns=("db/",)),
        cert_event(kr, "C7-n-l", N, LEADER, patterns=("db/prod/",)),
    ]


def small_graph_events(kr: Keyring, seal_digest: str) -> list[dict[str, Any]]:
    """9 个事件：批准 -> 7 张证书逐张到位 -> 上游撤回。"""
    events: list[dict[str, Any]] = [
        approval_event(
            kr,
            approval_id="AP-SMALL",
            signer=LEADER,
            serial="SMALL-1",
            agent_id="agent-a",
            seal_digest=seal_digest,
        )
    ]
    # 按“先形成第一条 R1 链，再补菱形第二支，最后 R2”的顺序插入
    certs = small_cert_events(kr)
    order_idx = [0, 1, 2, 3, 4, 5, 6]
    events.extend(certs[i] for i in order_idx)
    events.append(
        revocation_event(
            kr, revocation_id="REV-SMALL", target="AP-SMALL", issuer=U
        )
    )
    return events


# ----------------------------------------------------------------------
# 值班名单世界：9 个值班员，覆盖所有判定分支
# ----------------------------------------------------------------------
def _two_root_certs(
    kr: Keyring,
    tag: str,
    signer: str,
    org: str,
    *,
    diamond: bool = False,
    direct: bool = False,
    include_duty: bool = True,
    include_resource: bool = True,
) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    if direct:
        if include_duty:
            out.append(
                cert_event(
                    kr, f"C-{tag}-rd-l", ROOT_DUTY, signer,
                    org=org, patterns=("*",),
                )
            )
        if include_resource:
            out.append(
                cert_event(
                    kr, f"C-{tag}-rr-l", ROOT_RESOURCE, signer,
                    org=org, patterns=("*",),
                )
            )
        return out

    up = f"u-{tag}"
    com = f"c-{tag}"
    res = f"r-{tag}"
    if include_duty:
        out.append(cert_event(kr, f"C-{tag}-rd-u", ROOT_DUTY, up, org=org))
        if diamond:
            m1, m2 = f"m1-{tag}", f"m2-{tag}"
            out.append(cert_event(kr, f"C-{tag}-u-m1", up, m1, org=org))
            out.append(cert_event(kr, f"C-{tag}-u-m2", up, m2, org=org))
            out.append(cert_event(kr, f"C-{tag}-m1-l", m1, signer, org=org))
            out.append(cert_event(kr, f"C-{tag}-m2-l", m2, signer, org=org))
        else:
            out.append(cert_event(kr, f"C-{tag}-u-c", up, com, org=org))
            out.append(cert_event(kr, f"C-{tag}-c-l", com, signer, org=org))
    if include_resource:
        out.append(cert_event(kr, f"C-{tag}-rr-r", ROOT_RESOURCE, res, org=org))
        out.append(cert_event(kr, f"C-{tag}-r-l", res, signer, org=org))
    return out


ROSTER_SPECS: list[dict[str, Any]] = [
    {"key": "a", "agent": "agent-a", "mode": "ok"},
    {"key": "b", "agent": "agent-b", "mode": "diamond"},
    {"key": "c", "agent": "agent-c", "mode": "one_root"},
    {"key": "d", "agent": "agent-d", "mode": "expired"},
    {"key": "e", "agent": "agent-e", "mode": "scope"},
    {"key": "f", "agent": "agent-f", "mode": "seal"},
    {"key": "g", "agent": "agent-g", "mode": "revoked"},
    {"key": "h", "agent": "agent-h", "mode": "future"},
    {"key": "i", "agent": "agent-i", "mode": "direct"},
]


def build_roster_world(
    kr: Keyring, seal_digest: str
) -> dict[str, Any]:
    """构造名单世界。

    返回 events（各值班员块顺序拼接）与 blocks（每块的局部水位区间）。
    """
    events: list[dict[str, Any]] = []
    blocks: list[dict[str, Any]] = []

    for spec in ROSTER_SPECS:
        key = spec["key"]
        mode = spec["mode"]
        agent = spec["agent"]
        org = "north" if key in {"c", "f", "i"} else ("south" if key in {"d", "g"} else "east")
        signer = f"leader-{key}"
        approval_id = f"AP-{key.upper()}"
        start = len(events)

        lo, hi = TERM_LO, TERM_HI
        bound_digest = seal_digest
        patterns = ("db/prod/",)
        resource = "db/prod/primary"

        if mode == "expired":
            hi = AT - 10
        elif mode == "future":
            lo = AT + 100
        elif mode == "scope":
            patterns = ("cache/",)
            resource = "db/prod/primary"
        elif mode == "seal":
            bound_digest = WRONG_DIGEST

        ap = approval_event(
            kr,
            approval_id=approval_id,
            signer=signer,
            serial=f"ROSTER-{key.upper()}",
            agent_id=agent,
            seal_digest=bound_digest,
            org=org,
            patterns=patterns,
            resource=resource,
            lo=lo,
            hi=hi,
        )
        block = [ap]
        block.extend(
            _two_root_certs(
                kr,
                key,
                signer,
                org,
                diamond=(mode == "diamond"),
                direct=(mode == "direct"),
                include_resource=(mode != "one_root"),
            )
        )
        if mode == "revoked":
            # 找到 duty 链上的上游 commissioner 作为撤回人
            block.append(
                revocation_event(
                    kr,
                    revocation_id=f"REV-{key.upper()}",
                    target=approval_id,
                    issuer=f"c-{key}",
                )
            )

        events.extend(block)
        blocks.append(
            {
                "key": key,
                "agent": agent,
                "mode": mode,
                "approval_id": approval_id,
                "signer": signer,
                "org": org,
                "resource": resource,
                "start": start,
                "end": len(events),
                "local_watermarks": len(block),
            }
        )

    return {"events": events, "blocks": blocks}
