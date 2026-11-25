"""证书 DAG、上游溯源与“独立控制根”计票。

一条证书边 ``issuer -> subject`` 表示 issuer 把 scope/term 内的权力委派给
subject。从批准签署人向上回溯到受信控制根得到若干证书链。

独立性规则（题面核心）：

1. 批准必须拿到 ``POLICY_REQUIRED_ROOTS`` 个**不同控制根**的有效链；
2. 两条链即使路径不同（菱形委派），只要溯源到同一个上游控制根，就只算
   **一票**；报告中给出同源合并说明；
3. “最短独立证书”= 每个独立根取长度最短的有效链，再取总长度最短的
   两个不同根组合。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .canon import Keyring, verify
from .scope import Scope, Term


class InvalidCertificate(ValueError):
    pass


@dataclass(frozen=True)
class Cert:
    cert_id: str
    issuer: str
    subject: str
    scope: Scope
    term: Term
    seq: int | None = None
    raw: dict[str, Any] = field(default_factory=dict, compare=False)

    @classmethod
    def from_signed(
        cls,
        envelope: dict[str, Any],
        keyring: Keyring,
        seq: int | None = None,
    ) -> "Cert":
        if not verify(envelope, keyring):
            raise InvalidCertificate("证书签名验证失败")
        p = envelope["payload"]
        if p.get("typ") != "cert":
            raise InvalidCertificate("记录类型不是 cert")
        return cls(
            cert_id=str(p["cert_id"]),
            issuer=str(p["issuer"]),
            subject=str(p["subject"]),
            scope=Scope.from_obj(p["scope"]),
            term=Term.from_obj(p["term"]),
            seq=seq,
            raw=envelope,
        )

    def node_path(self) -> list[str]:
        """根在前的节点路径（单条边时为 [issuer, subject]）。"""
        return [self.issuer, self.subject]


@dataclass
class ChainInfo:
    certs: tuple[Cert, ...]

    @property
    def root(self) -> str:
        return self.certs[0].issuer

    @property
    def length(self) -> int:
        return len(self.certs)

    @property
    def node_path(self) -> list[str]:
        nodes = [self.certs[0].issuer]
        for c in self.certs:
            nodes.append(c.subject)
        return nodes

    @property
    def cert_ids(self) -> list[str]:
        return [c.cert_id for c in self.certs]

    def fork_upstream_with(self, other: "ChainInfo") -> str:
        """两条链最长公共节点前缀的最后一个节点（同源分叉点）。"""
        a, b = self.node_path, other.node_path
        fork = a[0]
        for x, y in zip(a, b):
            if x != y:
                break
            fork = x
        return fork

    def to_report(self) -> dict[str, Any]:
        return {
            "root": self.root,
            "length": self.length,
            "cert_ids": self.cert_ids,
            "node_path": self.node_path,
        }


@dataclass
class ProofResult:
    target: str
    at: int
    org: str
    resource: str
    all_chains: list[ChainInfo]
    eligible: list[ChainInfo]
    invalid: list[dict[str, Any]]
    shortest_by_root: dict[str, ChainInfo]
    required_roots: int

    @property
    def independent_roots(self) -> list[str]:
        return sorted(self.shortest_by_root)

    @property
    def root_votes(self) -> int:
        return len(self.shortest_by_root)

    @property
    def enough(self) -> bool:
        return self.root_votes >= self.required_roots

    @property
    def shortest_proof(self) -> list[ChainInfo]:
        roots = sorted(
            self.shortest_by_root,
            key=lambda r: (self.shortest_by_root[r].length, r),
        )[: self.required_roots]
        return [self.shortest_by_root[r] for r in roots]

    def collapse_notes(self) -> list[dict[str, Any]]:
        """每个拥有多条有效链的根，说明同源合并为一票。"""
        notes: list[dict[str, Any]] = []
        by_root: dict[str, list[ChainInfo]] = {}
        for ch in self.eligible:
            by_root.setdefault(ch.root, []).append(ch)
        for root, chains in sorted(by_root.items()):
            if len(chains) <= 1:
                continue
            chains = sorted(chains, key=lambda c: (c.length, "|".join(c.cert_ids)))
            fork = chains[0].fork_upstream_with(chains[1])
            notes.append(
                {
                    "root": root,
                    "raw_chain_count": len(chains),
                    "counted_votes": 1,
                    "shared_upstream": fork,
                    "chain_ids": [c.cert_ids for c in chains],
                    "note": (
                        f"{len(chains)} 条链同源于 {fork}（控制根 {root}），"
                        f"按上游去重只算 1 票"
                    ),
                }
            )
        return notes

    def to_report(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "at": self.at,
            "org": self.org,
            "resource": self.resource,
            "structural_chain_count": len(self.all_chains),
            "eligible_chain_count": len(self.eligible),
            "independent_roots": self.independent_roots,
            "root_votes": self.root_votes,
            "required_roots": self.required_roots,
            "enough": self.enough,
            "shortest_by_root": {
                r: c.to_report() for r, c in self.shortest_by_root.items()
            },
            "shortest_proof": [c.to_report() for c in self.shortest_proof],
            "collapse_notes": self.collapse_notes(),
            "invalid": self.invalid,
        }


class CertGraph:
    def __init__(self, trusted_roots: set[str], required_roots: int = 2) -> None:
        self.trusted_roots = set(trusted_roots)
        self.required_roots = required_roots
        self._by_subject: dict[str, list[Cert]] = {}
        self.certs: list[Cert] = []

    def add(self, cert: Cert) -> None:
        self.certs.append(cert)
        self._by_subject.setdefault(cert.subject, []).append(cert)

    # ---- 结构溯源 -------------------------------------------------------
    def structural_chains(self, target: str) -> list[ChainInfo]:
        found: list[tuple[Cert, ...]] = []

        def walk(node: str, upward: list[Cert], seen: set[str]) -> None:
            for cert in self._by_subject.get(node, ()):  # 边 cert.issuer -> node
                if cert.issuer in seen:
                    continue  # 防御环
                next_up = upward + [cert]
                if cert.issuer in self.trusted_roots:
                    found.append(tuple(reversed(next_up)))
                else:
                    walk(cert.issuer, next_up, seen | {cert.issuer})

        walk(target, [], {target})
        # 确定性排序
        found.sort(key=lambda cs: (len(cs), "|".join(c.cert_id for c in cs)))
        return [ChainInfo(certs=cs) for cs in found]

    # ---- 单链有效性 -----------------------------------------------------
    @staticmethod
    def check_chain(
        chain: ChainInfo, at: int, org: str, resource: str
    ) -> tuple[bool, str | None]:
        for c in chain.certs:
            if not c.term.contains(at):
                return False, f"CERT_TERM_EXPIRED_OR_PREMATURE:{c.cert_id}"

        for upper, lower in zip(chain.certs, chain.certs[1:]):
            if not upper.term.covers(lower.term):
                return False, f"TERM_NOT_ATTENUATED:{lower.cert_id}"
            if not upper.scope.covers_scope(lower.scope):
                return False, f"SCOPE_NOT_ATTENUATED:{lower.cert_id}"

        last = chain.certs[-1]
        if last.subject != chain.node_path[-1]:  # 恒真，保留作结构自检
            return False, "BROKEN_CHAIN"
        if not last.scope.covers_resource(org, resource):
            return False, f"CHAIN_SCOPE_DENIED:{last.cert_id}"
        return True, None

    # ---- 计票与最短证明 -------------------------------------------------
    def proof_for(
        self, target: str, at: int, org: str, resource: str
    ) -> ProofResult:
        chains = self.structural_chains(target)
        eligible: list[ChainInfo] = []
        invalid: list[dict[str, Any]] = []
        for ch in chains:
            ok, reason = self.check_chain(ch, at, org, resource)
            if ok:
                eligible.append(ch)
            else:
                invalid.append({"chain": ch.cert_ids, "reason": reason})

        shortest: dict[str, ChainInfo] = {}
        for ch in sorted(eligible, key=lambda c: (c.length, "|".join(c.cert_ids))):
            shortest.setdefault(ch.root, ch)

        return ProofResult(
            target=target,
            at=at,
            org=org,
            resource=resource,
            all_chains=chains,
            eligible=eligible,
            invalid=invalid,
            shortest_by_root=shortest,
            required_roots=self.required_roots,
        )
