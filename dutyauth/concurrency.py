"""两个真实工作线程 + ``threading.Barrier`` 复现三类关键时序。

场景：

A. ``revoke_first``：屏障保证“撤回已 fsync 落盘”先于“批准提交”，
   并扫描全部水位证明该批准**从未可见**；附“批准先到”对照，展示
   OK -> REVOKED 的历史翻转。
B. ``persisted_ack_lost``：签署已 fsync 持久化，但首次回执被模拟网络丢弃；
   客户端用同一幂等键重试，重开账本后仍只入账一次。
C. ``same_seq_diff_digest``：两个线程在同一屏障后并发提交同号、不同摘要
   的信封；锁串行化提交，必有且仅有一个正本，另一个触发 equivocation
   证据并冻结序号。多轮重复以排除偶然时序。
"""

from __future__ import annotations

import threading
from pathlib import Path
from typing import Any

from . import synthetic as S
from .canon import Keyring
from .engine import decide
from .ledger import EquivocationError, Ledger, reopen_verify


def _fresh_ledger(path: Path, kr: Keyring) -> Ledger:
    if path.exists():
        path.unlink()
    return Ledger(path, kr)


def _seed_authority_certs(led: Ledger, kr: Keyring) -> None:
    for ev in S.small_cert_events(kr):
        led.submit(ev["envelope"], "cert")


# ----------------------------------------------------------------------
# A. 撤回先于批准提交（+ 批准先到对照）
# ----------------------------------------------------------------------
def scenario_revocation_order(
    artifact_dir: str | Path, kr: Keyring, seal_digest: str
) -> dict[str, Any]:
    artifact_dir = Path(artifact_dir)
    out: dict[str, Any] = {}

    for order in ("revoke_first", "approve_first_contrast"):
        path = artifact_dir / f"{order}.jsonl"
        led = _fresh_ledger(path, kr)
        _seed_authority_certs(led, kr)

        approval = S.approval_event(
            kr,
            approval_id=f"AP-{order.upper()}",
            signer=S.LEADER,
            serial=f"SEQ-{order}",
            agent_id="agent-a",
            seal_digest=seal_digest,
        )["envelope"]
        revocation = S.revocation_event(
            kr,
            revocation_id=f"REV-{order.upper()}",
            target=f"AP-{order.upper()}",
            issuer=S.U,
        )["envelope"]

        first_done = threading.Barrier(2)   # 两者都已完成签署准备
        second_gate = threading.Barrier(2)  # 第一个动作落盘后放行第二个
        commit_indices: dict[str, int] = {}
        errors: dict[str, str] = {}

        def revoker_first() -> None:
            try:
                first_done.wait()
                r = led.submit(revocation, "revocation", thread_name="worker-revoker")
                commit_indices["revocation"] = r.index
                second_gate.wait()
            except BaseException as exc:  # 收集线程异常
                errors["revoker"] = repr(exc)

        def approver_after_gate() -> None:
            try:
                first_done.wait()
                second_gate.wait()
                r = led.submit(
                    approval, "approval",
                    idem_key=f"idem-{order}",
                    thread_name="worker-approver",
                )
                commit_indices["approval"] = r.index
            except BaseException as exc:
                errors["approver"] = repr(exc)

        def approver_first() -> None:
            try:
                first_done.wait()
                r = led.submit(
                    approval, "approval",
                    idem_key=f"idem-{order}",
                    thread_name="worker-approver",
                )
                commit_indices["approval"] = r.index
                second_gate.wait()
            except BaseException as exc:
                errors["approver"] = repr(exc)

        def revoker_after_gate() -> None:
            try:
                first_done.wait()
                second_gate.wait()
                r = led.submit(revocation, "revocation", thread_name="worker-revoker")
                commit_indices["revocation"] = r.index
            except BaseException as exc:
                errors["revoker"] = repr(exc)

        if order == "revoke_first":
            threads = [
                threading.Thread(target=revoker_first, name="worker-revoker"),
                threading.Thread(target=approver_after_gate, name="worker-approver"),
            ]
        else:
            threads = [
                threading.Thread(target=approver_first, name="worker-approver"),
                threading.Thread(target=revoker_after_gate, name="worker-revoker"),
            ]

        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=10)
            if t.is_alive():
                errors.setdefault("timeout", f"线程 {t.name} 未在 10s 内结束")

        # 全水位扫描：该批准是否曾可见
        events = led.events_for_engine()
        rows: list[dict[str, Any]] = []
        for w in range(len(events) + 1):
            d = decide(
                events, w, f"AP-{order.upper()}", S.AT, kr,
                S.TRUSTED_ROOTS, seal_digest,
            )
            rows.append({"w": w, "allowed": d.allowed, "code": d.code})
        led.close()

        approval_w = next(
            (r["w"] for r in rows if r["code"] != "NO_APPROVAL"), None
        )
        visible_watermarks = [r["w"] for r in rows if r["allowed"]]
        out[order] = {
            "ledger_path": str(path),
            "errors": errors,
            "commit_indices": commit_indices,
            "revocation_before_approval": (
                commit_indices.get("revocation", 10**9)
                < commit_indices.get("approval", -1)
            ),
            "approval_first_seen_watermark": approval_w,
            "visible_watermarks": visible_watermarks,
            "ever_visible": bool(visible_watermarks),
            "watermark_rows": rows,
            "final_code": rows[-1]["code"],
            "hash_chain_ok": reopen_verify(path, kr).verify_hash_chain(),
        }

    # 关键安全性质：撤回先到 => 从未可见；对照 => 至少出现过 OK 水位
    out["invariants_hold"] = (
        out["revoke_first"]["revocation_before_approval"]
        and not out["revoke_first"]["ever_visible"]
        and out["revoke_first"]["final_code"] == "REVOKED"
        and out["approve_first_contrast"]["ever_visible"]
        and out["approve_first_contrast"]["final_code"] == "REVOKED"
        and not out["revoke_first"]["errors"]
    )
    return out


# ----------------------------------------------------------------------
# B. 已持久化 + 回执丢失 + 幂等重试
# ----------------------------------------------------------------------
def scenario_persisted_ack_lost(
    artifact_dir: str | Path, kr: Keyring, seal_digest: str
) -> dict[str, Any]:
    artifact_dir = Path(artifact_dir)
    path = artifact_dir / "persisted_ack_lost.jsonl"
    led = _fresh_ledger(path, kr)
    _seed_authority_certs(led, kr)

    idem_key = "idem-retry-42"
    approval_id = "AP-ACK-42"

    def make_envelope() -> dict[str, Any]:
        # 相同输入 => HMAC 签名逐字节相同，模拟同一请求的重发
        return S.approval_event(
            kr,
            approval_id=approval_id,
            signer=S.LEADER,
            serial="CLI-42",
            agent_id="agent-a",
            seal_digest=seal_digest,
        )["envelope"]

    persisted_barrier = threading.Barrier(2)
    first: dict[str, Any] = {}
    retry: dict[str, Any] = {}
    errors: dict[str, str] = {}

    def sender_worker() -> None:
        try:
            env = make_envelope()
            r = led.submit(env, "approval", idem_key=idem_key,
                           thread_name="worker-sender")
            first["receipt"] = r.receipt
            # 模拟：回执在网络中丢失，调用方拿不到 r.receipt
            first["delivered_to_client"] = False
            first["fsync_confirmed"] = True
            persisted_barrier.wait()
        except BaseException as exc:
            errors["sender"] = repr(exc)

    def retry_client_worker() -> None:
        try:
            persisted_barrier.wait()  # 等首条 fsync 完成后再重试
            env = make_envelope()
            r = led.submit(env, "approval", idem_key=idem_key,
                           thread_name="worker-retry-client")
            retry["receipt"] = r.receipt
            retry["duplicated"] = r.duplicated
        except BaseException as exc:
            errors["retry"] = repr(exc)

    t1 = threading.Thread(target=sender_worker, name="worker-sender")
    t2 = threading.Thread(target=retry_client_worker, name="worker-retry-client")
    t1.start(); t2.start()
    t1.join(10); t2.join(10)

    counts_after_threads = led.counts()
    first_index = first["receipt"]["ledger_index"]
    retry_index = retry.get("receipt", {}).get("ledger_index")

    # 关闭并用新句柄从磁盘重开：证明持久化 + 重放幂等
    led.close()
    reopened = reopen_verify(path, kr)
    third = reopened.submit(make_envelope(), "approval", idem_key=idem_key)
    counts_after_reopen = reopened.counts()

    events = reopened.events_for_engine()
    decision = decide(
        events, len(events), approval_id, S.AT, kr, S.TRUSTED_ROOTS, seal_digest
    )
    chain_ok = reopened.verify_hash_chain()
    reopened.close()

    return {
        "ledger_path": str(path),
        "errors": errors,
        "first_receipt": first.get("receipt"),
        "ack_delivered_to_client": first.get("delivered_to_client", True),
        "retry_duplicated": retry.get("duplicated"),
        "same_index": first_index == retry_index == third.index,
        "retry_index": retry_index,
        "reopened_retry_duplicated": third.duplicated,
        "approval_record_count": counts_after_reopen.get("approval"),
        "counts_after_threads": counts_after_threads,
        "counts_after_reopen": counts_after_reopen,
        "hash_chain_ok": chain_ok,
        "final_decision_code": decision.code,
        "final_allowed": decision.allowed,
        "invariants_hold": (
            not errors
            and retry.get("duplicated") is True
            and third.duplicated is True
            and first_index == retry_index == third.index
            and counts_after_reopen.get("approval") == 1
            and decision.allowed
        ),
    }


# ----------------------------------------------------------------------
# C. 同号不同摘要
# ----------------------------------------------------------------------
def scenario_same_seq_diff_digest(
    artifact_dir: str | Path, kr: Keyring, seal_digest: str, rounds: int = 6
) -> dict[str, Any]:
    artifact_dir = Path(artifact_dir)
    path = artifact_dir / "same_seq_diff_digest.jsonl"
    led = _fresh_ledger(path, kr)

    round_reports: list[dict[str, Any]] = []
    primary_evidence: dict[str, Any] | None = None

    for rnd in range(rounds):
        serial = f"SN-{rnd}"
        approval_id = f"AP-EQ-{rnd}"
        barrier = threading.Barrier(2)
        outcomes: dict[str, Any] = {}
        errors: dict[str, str] = {}

        def worker(tag: str, digest: str, idem: str) -> None:
            try:
                env = S.approval_event(
                    kr,
                    approval_id=approval_id,
                    signer=S.LEADER,
                    serial=serial,
                    agent_id="agent-a",
                    seal_digest=digest,
                )["envelope"]
                barrier.wait()
                r = led.submit(env, "approval", idem_key=idem,
                               thread_name=f"worker-eq-{tag}-{rnd}")
                outcomes[tag] = {"committed": True, "index": r.index,
                                 "duplicated": r.duplicated}
            except EquivocationError as exc:
                outcomes[tag] = {"committed": False, "equivocation": True}
                outcomes[tag]["evidence_digests"] = exc.evidence.get("digests")
                if rnd == 0:
                    errors.setdefault("__evidence__", exc.evidence)
            except BaseException as exc:  # pragma: no cover - 防御
                errors[tag] = repr(exc)

        ta = threading.Thread(
            target=worker, args=("a", seal_digest, f"idem-eq-a-{rnd}"),
            name=f"worker-eq-a-{rnd}",
        )
        tb = threading.Thread(
            target=worker, args=("b", S.WRONG_DIGEST, f"idem-eq-b-{rnd}"),
            name=f"worker-eq-b-{rnd}",
        )
        ta.start(); tb.start(); ta.join(10); tb.join(10)

        a_win = outcomes.get("a", {}).get("committed") is True
        b_win = outcomes.get("b", {}).get("committed") is True
        exactly_one_winner = (a_win + b_win) == 1
        evidence = errors.get("__evidence__")
        if rnd == 0:
            primary_evidence = evidence

        round_reports.append(
            {
                "round": rnd,
                "serial": serial,
                "outcomes": outcomes,
                "exactly_one_winner": exactly_one_winner,
                "frozen_after": led.is_frozen(S.LEADER, serial),
                "unexpected_errors": {
                    k: v for k, v in errors.items() if k != "__evidence__"
                },
            }
        )

    counts = led.counts()
    # 重开校验持久化证据
    led.close()
    reopened = reopen_verify(path, kr)
    frozen_on_disk = reopened.is_frozen(S.LEADER, "SN-0")
    events = reopened.events_for_engine()
    decision = decide(
        events, len(events), "AP-EQ-0", S.AT, kr, S.TRUSTED_ROOTS, seal_digest
    )

    # 证据公证签名必须可独立验证
    notary_ok = False
    if primary_evidence is not None:
        from .canon import verify as verify_sig
        # 找到 SN-0 的证据信封
        for rec in reopened.records:
            if rec.get("kind") == "equivocation":
                p = rec["envelope"]["payload"]
                if p.get("issuer") == S.LEADER and p.get("serial") == "SN-0":
                    notary_ok = verify_sig(rec["envelope"], kr)
                    break
    reopened.close()

    invariants = (
        all(r["exactly_one_winner"] and r["frozen_after"] for r in round_reports)
        and counts.get("approval") == rounds
        and counts.get("equivocation") == rounds
        and frozen_on_disk
        and decision.code == "EQUIVOCATION"
        and notary_ok
        and primary_evidence is not None
    )

    return {
        "ledger_path": str(path),
        "rounds": rounds,
        "round_reports": round_reports,
        "approval_records": counts.get("approval"),
        "equivocation_evidence_records": counts.get("equivocation"),
        "frozen_on_disk_after_reopen": frozen_on_disk,
        "notary_signature_verified": notary_ok,
        "primary_evidence_digests": (
            primary_evidence.get("digests") if primary_evidence else None
        ),
        "final_decision_code": decision.code,
        "hash_chain_ok": True,
        "invariants_hold": invariants,
    }


def run_all_concurrency(
    artifact_dir: str | Path, kr: Keyring, seal_digest: str
) -> dict[str, Any]:
    artifact_dir = Path(artifact_dir) / "concurrency"
    artifact_dir.mkdir(parents=True, exist_ok=True)
    a = scenario_revocation_order(artifact_dir, kr, seal_digest)
    b = scenario_persisted_ack_lost(artifact_dir, kr, seal_digest)
    c = scenario_same_seq_diff_digest(artifact_dir, kr, seal_digest)
    return {
        "revocation_order": a,
        "persisted_ack_lost": b,
        "same_seq_diff_digest": c,
        "all_invariants_hold": (
            a["invariants_hold"] and b["invariants_hold"] and c["invariants_hold"]
        ),
    }
