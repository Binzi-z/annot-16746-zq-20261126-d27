"""任期与资源范围。

时间使用确定性的逻辑整数（合成时钟），区间为半开 ``[not_before, not_after)``。
资源范围按“组织 + 路径前缀”建模：

- ``"*"``      覆盖该组织全部资源
- ``"db/"``    路径前缀，覆盖 ``db/`` 之下所有资源
- ``"db/x"``   精确资源

委派证书的范围只能逐跳收窄；子范围必须被父范围覆盖。
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable


@dataclass(frozen=True, order=True)
class Term:
    not_before: int
    not_after: int

    def __post_init__(self) -> None:
        if self.not_after <= self.not_before:
            raise ValueError("任期必须满足 not_before < not_after")

    def contains(self, at: int) -> bool:
        return self.not_before <= at < self.not_after

    def covers(self, child: "Term") -> bool:
        """父任期是否完整覆盖子任期（允许端点相等）。"""
        return (
            self.not_before <= child.not_before
            and child.not_after <= self.not_after
        )

    def to_obj(self) -> dict[str, int]:
        return {"not_before": self.not_before, "not_after": self.not_after}

    @classmethod
    def from_obj(cls, obj: dict[str, Any]) -> "Term":
        return cls(int(obj["not_before"]), int(obj["not_after"]))


@dataclass(frozen=True)
class Scope:
    org: str
    patterns: tuple[str, ...]

    def __post_init__(self) -> None:
        if not self.patterns:
            raise ValueError("资源范围至少需要一个模式")
        object.__setattr__(self, "patterns", tuple(sorted(self.patterns)))

    # ---- 资源匹配 -------------------------------------------------------
    @staticmethod
    def _pattern_covers_resource(pattern: str, resource: str) -> bool:
        if pattern == "*":
            return True
        if pattern.endswith("/"):
            return resource.startswith(pattern)
        return pattern == resource

    def covers_resource(self, org: str, resource: str) -> bool:
        if org != self.org:
            return False
        return any(self._pattern_covers_resource(p, resource) for p in self.patterns)

    # ---- 范围收窄 -------------------------------------------------------
    @staticmethod
    def _pattern_covers_pattern(parent: str, child: str) -> bool:
        if parent == "*":
            return True
        if child == "*":
            return False
        if child.endswith("/"):
            # 子是前缀：父也必须是更宽或相等的前缀
            return parent.endswith("/") and child.startswith(parent)
        # child 是精确资源
        return parent == child or (
            parent.endswith("/") and child.startswith(parent)
        )

    def covers_scope(self, child: "Scope") -> bool:
        if child.org != self.org:
            return False
        return all(
            any(self._pattern_covers_pattern(p, cp) for p in self.patterns)
            for cp in child.patterns
        )

    def to_obj(self) -> dict[str, Any]:
        return {"org": self.org, "patterns": list(self.patterns)}

    @classmethod
    def from_obj(cls, obj: dict[str, Any]) -> "Scope":
        return cls(org=str(obj["org"]), patterns=tuple(obj["patterns"]))


def scope_from(obj_or_scope: dict[str, Any] | Scope) -> Scope:
    return obj_or_scope if isinstance(obj_or_scope, Scope) else Scope.from_obj(obj_or_scope)


def term_from(obj_or_term: dict[str, Any] | Term) -> Term:
    return obj_or_term if isinstance(obj_or_term, Term) else Term.from_obj(obj_or_term)


def flatten_patterns(scopes: Iterable[Scope]) -> set[str]:
    out: set[str] = set()
    for s in scopes:
        out.update(s.patterns)
    return out
