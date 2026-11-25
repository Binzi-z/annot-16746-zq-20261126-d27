"""六万条按组织分组的代理事件：插入一条撤回后的重算范围与全量一致性。

设计要点：

- 确定性合成（固定随机种子 16746），20 个组织各 3000 条，连续分组；
- 每条访问类事件带 ``access_count``（真实资源访问次数），聚合时求和，
  不用估算值；
- 分区存储 + IO 计量器：每次重算实际读取了多少条事件都被计数，用
  **实际读取条数**证明“单组织撤回只触发该组织分区重算”，而不是口头声称；
- 增量（仅受影响组织）结果与全量重算结果逐组织、逐代理、逐资源、逐计数
  比对，并比较规范化状态摘要，保证完全一致；
- 撤回只改变“当前可见权限”，不改变不可变的历史访问计数。
"""

from __future__ import annotations

import random
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any

from .canon import Keyring, digest_obj
from .synthetic import revocation_event

ORG_COUNT = 20
PER_ORG = 3000
BASE_EVENTS = ORG_COUNT * PER_ORG  # 60000
AFFECTED_ORG = "org-07"
SEED = 16746

AGENTS_PER_ORG = 40
RESOURCES = (
    "db/prod/primary",
    "db/prod/replica",
    "cache/session",
    "mq/orders",
    "object/reports",
    "sec/vault",
)
EVENT_KINDS = ("access", "access", "access", "check", "sync", "heartbeat")


# ----------------------------------------------------------------------
# 合成数据
# ----------------------------------------------------------------------
def generate_base_events() -> list[dict[str, Any]]:
    rng = random.Random(SEED)
    events: list[dict[str, Any]] = []
    global_seq = 0
    for o in range(ORG_COUNT):
        org = f"org-{o:02d}"
        for j in range(PER_ORG):
            kind = rng.choice(EVENT_KINDS)
            agent_idx = rng.randrange(AGENTS_PER_ORG)
            event = {
                "seq": global_seq,
                "org": org,
                "event_id": f"E-{global_seq:06d}",
                "agent_id": f"agent-{org}-{agent_idx:02d}",
                "kind": kind,
                "at": 1_759_000_000 + global_seq * 7,
                "resource": rng.choice(RESOURCES) if kind == "access" else None,
                # 仅 access 事件产生真实访问次数，1..12
                "access_count": rng.randint(1, 12) if kind == "access" else 0,
            }
            events.append(event)
            global_seq += 1
    return events


def insert_revocation(
    events: list[dict[str, Any]],
    kr: Keyring,
    *,
    org: str = AFFECTED_ORG,
    target_permission: str = "perm-org-07-db-prod",
) -> list[dict[str, Any]]:
    """在指定组织分组的末尾补入一条已签署撤回（总数变为 60001）。"""
    out = [dict(e) for e in events]
    rev = {
        "seq": len(out),
        "org": org,
        "event_id": f"E-REV-{org}",
        "agent_id": "control-root-duty",
        "kind": "revocation",
        "at": 1_760_100_000,
        "resource": None,
        "access_count": 0,
        "target_permission": target_permission,
        "envelope": revocation_event(
            kr,
            revocation_id=f"REV-SCALE-{org}",
            target=target_permission,
            issuer="root-duty",
            reason="rotation-after-incident",
        )["envelope"],
    }
    out.append(rev)
    return out


# ----------------------------------------------------------------------
# 带实际读取计量的分区存储
# ----------------------------------------------------------------------
@dataclass
class ReadMeter:
    records_read: int = 0
    org_reads: dict[str, int] = field(default_factory=lambda: defaultdict(int))
    full_scans: int = 0
    scoped_recomputes: int = 0

    def note_read(self, org: str, n: int = 1) -> None:
        self.records_read += n
        self.org_reads[org] += n

    def snapshot(self) -> dict[str, Any]:
        return {
            "records_read": self.records_read,
            "org_reads": dict(sorted(self.org_reads.items())),
            "full_scans": self.full_scans,
            "scoped_recomputes": self.scoped_recomputes,
        }


class PartitionedEventStore:
    def __init__(self, events: list[dict[str, Any]]) -> None:
        self.by_org: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for e in events:
            self.by_org[e["org"]].append(e)
        for org in self.by_org:
            self.by_org[org].sort(key=lambda e: e["seq"])
        self.meter = ReadMeter()

    def read_org(self, org: str) -> list[dict[str, Any]]:
        rows = self.by_org.get(org, [])
        # 逐条计量，模拟真实扫描成本
        for _ in rows:
            self.meter.note_read(org, 1)
        self.meter.scoped_recomputes += 1
        return list(rows)

    def read_all_grouped(self) -> dict[str, list[dict[str, Any]]]:
        self.meter.full_scans += 1
        grouped: dict[str, list[dict[str, Any]]] = {}
        for org, rows in sorted(self.by_org.items()):
            copied: list[dict[str, Any]] = []
            for e in rows:
                self.meter.note_read(org, 1)
                copied.append(e)
            grouped[org] = copied
        return grouped

    def org_count(self, org: str) -> int:
        return len(self.by_org.get(org, []))


# ----------------------------------------------------------------------
# 重算：纯函数 fold
# ----------------------------------------------------------------------
def recompute_org_state(org: str, rows: list[dict[str, Any]]) -> dict[str, Any]:
    total_accesses = 0
    access_events = 0
    by_agent: dict[str, int] = defaultdict(int)
    by_resource: dict[str, int] = defaultdict(int)
    event_kind_counts: dict[str, int] = defaultdict(int)
    revocations: list[str] = []
    visible_permissions: set[str] = {
        # 合成基线：每个组织默认持有两个资源权限
        f"perm-{org}-db-prod",
        f"perm-{org}-cache-session",
    }

    for e in rows:
        event_kind_counts[e["kind"]] += 1
        ac = int(e.get("access_count") or 0)
        if e["kind"] == "access":
            access_events += 1
            total_accesses += ac
            by_agent[e["agent_id"]] += ac
            if e.get("resource"):
                by_resource[e["resource"]] += ac
        if e["kind"] == "revocation":
            target = e.get("target_permission")
            revocations.append(e["event_id"])
            if target:
                visible_permissions.discard(target)

    state = {
        "org": org,
        "event_count": len(rows),
        "access_events": access_events,
        "actual_access_total": total_accesses,
        "accesses_by_agent": dict(sorted(by_agent.items())),
        "accesses_by_resource": dict(sorted(by_resource.items())),
        "kind_counts": dict(sorted(event_kind_counts.items())),
        "revocations": revocations,
        "current_visible_permissions": sorted(visible_permissions),
    }
    # 规范化摘要：任何字段差异都会改变
    state["state_digest"] = digest_obj(
        {k: v for k, v in state.items() if k != "state_digest"}
    )
    return state


def full_recompute(store: PartitionedEventStore) -> dict[str, dict[str, Any]]:
    grouped = store.read_all_grouped()
    return {org: recompute_org_state(org, rows) for org, rows in grouped.items()}


def scoped_recompute(
    store: PartitionedEventStore, org: str
) -> dict[str, Any]:
    return recompute_org_state(org, store.read_org(org))


# ----------------------------------------------------------------------
# 端到端核对
# ----------------------------------------------------------------------
def run_scale_check(kr: Keyring) -> dict[str, Any]:
    base = generate_base_events()
    assert len(base) == BASE_EVENTS

    # 撤回前先做一次全量基线
    store_before = PartitionedEventStore(base)
    before_full = full_recompute(store_before)
    baseline_org_state = before_full[AFFECTED_ORG]

    # 插入一条撤回
    events = insert_revocation(base, kr)
    assert len(events) == 60001
    store = PartitionedEventStore(events)

    affected_rows = store.org_count(AFFECTED_ORG)
    assert affected_rows == PER_ORG + 1

    # 1) 组织级增量重算（只读取受影响组织）
    meter_before = store.meter.snapshot()
    scoped_state = scoped_recompute(store, AFFECTED_ORG)
    scoped_meter = store.meter.snapshot()
    scoped_reads = scoped_meter["records_read"] - meter_before["records_read"]
    other_org_reads_during_scope = sum(
        n
        for o, n in scoped_meter["org_reads"].items()
        if o != AFFECTED_ORG
    )

    # 2) 全量重算（用前后快照差值计量本次全量实际读取条数）
    before_full_meter = store.meter.snapshot()["records_read"]
    full_states = full_recompute(store)
    after_full_meter = store.meter.snapshot()
    full_reads = after_full_meter["records_read"] - before_full_meter

    # 3) 一致性：增量 vs 全量（受影响组织）
    scoped_equals_full = scoped_state == full_states[AFFECTED_ORG]

    # 4) 全量 vs 撤回前：除受影响组织外全部一致；受影响组织仅权限/撤回变化，
    #    历史访问计数必须保持不变
    untouched_orgs_identical = True
    untouched: list[str] = []
    for org, st in full_states.items():
        if org == AFFECTED_ORG:
            continue
        untouched.append(org)
        if st != before_full[org]:
            untouched_orgs_identical = False

    historical_counts_stable = (
        scoped_state["actual_access_total"]
        == baseline_org_state["actual_access_total"]
        and scoped_state["accesses_by_agent"]
        == baseline_org_state["accesses_by_agent"]
        and scoped_state["accesses_by_resource"]
        == baseline_org_state["accesses_by_resource"]
        and scoped_state["access_events"] == baseline_org_state["access_events"]
    )
    permission_revoked = (
        "perm-org-07-db-prod" not in scoped_state["current_visible_permissions"]
        and "perm-org-07-db-prod"
        in baseline_org_state["current_visible_permissions"]
    )

    # 5) 实际访问次数的独立交叉求和（换一种遍历方式）
    cross_total = sum(
        int(e.get("access_count") or 0)
        for e in store.by_org[AFFECTED_ORG]
        if e["kind"] == "access"
    )
    access_total_cross_check = cross_total == scoped_state["actual_access_total"]

    # 6) 所有组织的增量逐个重算，与一次全量逐组织比对（“全量一致”）
    per_org_consistency: dict[str, bool] = {}
    for org in sorted(store.by_org):
        per_org_consistency[org] = (
            scoped_recompute(store, org) == full_states[org]
        )
    all_orgs_consistent = all(per_org_consistency.values())

    total_actual_accesses_all_orgs = sum(
        st["actual_access_total"] for st in full_states.values()
    )

    invariants = (
        scoped_reads == PER_ORG + 1
        and other_org_reads_during_scope == 0
        and scoped_equals_full
        and untouched_orgs_identical
        and historical_counts_stable
        and permission_revoked
        and access_total_cross_check
        and all_orgs_consistent
        and full_reads == 60001
    )

    return {
        "seed": SEED,
        "organizations": ORG_COUNT,
        "per_org_base_events": PER_ORG,
        "base_event_count": BASE_EVENTS,
        "after_revocation_event_count": len(events),
        "affected_org": AFFECTED_ORG,
        "affected_org_rows": affected_rows,
        "scoped_recompute": {
            "records_actually_read": scoped_reads,
            "other_org_records_read": other_org_reads_during_scope,
            "expected_scope_rows": PER_ORG + 1,
            "reads_match_scope": scoped_reads == PER_ORG + 1,
        },
        "full_recompute": {
            "records_actually_read": full_reads,
            "full_scans": after_full_meter["full_scans"],
        },
        "scope_ratio_vs_full": round(scoped_reads / 60001, 4),
        "scoped_equals_full_affected_org": scoped_equals_full,
        "all_orgs_scoped_equal_full": all_orgs_consistent,
        "per_org_consistency": per_org_consistency,
        "untouched_orgs_count": len(untouched),
        "untouched_orgs_identical": untouched_orgs_identical,
        "historical_access_counts_stable": historical_counts_stable,
        "permission_revoked_in_current_view": permission_revoked,
        "access_total_cross_check": access_total_cross_check,
        "affected_org_actual_access_total": scoped_state["actual_access_total"],
        "all_orgs_actual_access_total": total_actual_accesses_all_orgs,
        "affected_org_current_permissions": scoped_state[
            "current_visible_permissions"
        ],
        "affected_org_revocations": scoped_state["revocations"],
        "affected_org_state_digest": scoped_state["state_digest"],
        "meter_final": store.meter.snapshot(),
        "invariants_hold": invariants,
    }
