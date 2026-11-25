"""持久化、幂等、可检测同号异摘要（equivocation）的只追加账本。

保证：

- 每条记录先写 JSONL、``flush`` + ``os.fsync`` 后才把回执交给调用方；
- 记录带 SHA-256 哈希链，重开文件可重放并校验；
- 相同幂等键 + 相同内容摘要的重试**不重复入账**，返回同一索引；
- 相同 ``(issuer, serial)`` 但内容摘要不同的第二次提交，原始双信封连同
  公证签名的 equivocation 证据一起落盘，该序号永久冻结，绝不覆盖首记录；
- 全部“检查 + 提交”在同一把锁内完成，供真实线程并发调用。
"""

from __future__ import annotations

import json
import os
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .canon import Keyring, digest_obj, envelope_digest, sign

NOTARY_ID = "control-notary"


class LedgerError(RuntimeError):
    pass


class IdempotencyKeyConflict(LedgerError):
    """同一个幂等键携带了不同内容。"""

    def __init__(self, message: str, *, idem_key: str, existing_index: int) -> None:
        super().__init__(message)
        self.idem_key = idem_key
        self.existing_index = existing_index


class EquivocationError(LedgerError):
    """同号不同摘要；证据已持久化。"""

    def __init__(self, message: str, *, evidence: dict[str, Any]) -> None:
        super().__init__(message)
        self.evidence = evidence


@dataclass
class CommitResult:
    index: int
    record_hash: str
    duplicated: bool
    receipt: dict[str, Any]
    record: dict[str, Any]


class Ledger:
    def __init__(self, path: str | Path, keyring: Keyring | None = None) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.keyring = keyring or Keyring()
        self._lock = threading.RLock()
        self._fh = open(self.path, "a", encoding="utf-8", newline="\n")
        self.records: list[dict[str, Any]] = []
        self._idem: dict[str, int] = {}
        # (issuer, serial) -> {"index": int, "digest": str, "frozen": bool,
        #                      "digests": set[str], "evidence": [indexes]}
        self._seq: dict[tuple[str, str], dict[str, Any]] = {}
        self._replay_unlocked()

    # ------------------------------------------------------------------
    # 重放
    # ------------------------------------------------------------------
    def _replay_unlocked(self) -> None:
        if not self.path.exists() or self.path.stat().st_size == 0:
            return
        with open(self.path, "r", encoding="utf-8") as fh:
            for line_no, line in enumerate(fh, 1):
                line = line.strip()
                if not line:
                    continue
                rec = json.loads(line)
                expected_index = len(self.records)
                if rec.get("ledger_index") != expected_index:
                    raise LedgerError(f"账本索引不连续，第 {line_no} 行")
                self.records.append(rec)
                idem = rec.get("idem_key")
                if idem:
                    self._idem[idem] = rec["ledger_index"]
                if rec.get("kind") == "equivocation":
                    ev = rec.get("envelope", {}).get("payload", {})
                    key = (ev.get("issuer", ""), str(ev.get("serial")))
                    entry = self._seq.setdefault(
                        key,
                        {
                            "index": None,
                            "digest": None,
                            "frozen": True,
                            "digests": set(),
                            "evidence": [],
                        },
                    )
                    entry["frozen"] = True
                    entry["evidence"].append(rec["ledger_index"])
                    for d in ev.get("digests", []):
                        entry["digests"].add(d)
                    continue
                issuer = rec.get("issuer")
                serial = rec.get("serial")
                if issuer is not None and serial is not None:
                    key = (issuer, str(serial))
                    digest = rec["content_digest"]
                    if key in self._seq and self._seq[key]["digest"] != digest:
                        # 正常路径不会出现：异摘要一定先写了证据
                        entry = self._seq[key]
                        entry["frozen"] = True
                        entry["digests"].add(digest)
                    else:
                        self._seq[key] = {
                            "index": rec["ledger_index"],
                            "digest": digest,
                            "frozen": self._seq.get(key, {}).get("frozen", False),
                            "digests": {digest},
                            "evidence": self._seq.get(key, {}).get("evidence", []),
                        }

    def verify_hash_chain(self) -> bool:
        prev = "0" * 64
        for i, rec in enumerate(self.records):
            if rec["ledger_index"] != i:
                return False
            if rec["prev_hash"] != prev:
                return False
            stored = rec["record_hash"]
            core = {k: v for k, v in rec.items() if k != "record_hash"}
            if digest_obj(core) != stored:
                return False
            prev = stored
        return True

    @property
    def head_hash(self) -> str:
        return self.records[-1]["record_hash"] if self.records else "0" * 64

    def close(self) -> None:
        with self._lock:
            if not self._fh.closed:
                self._fh.flush()
                os.fsync(self._fh.fileno())
                self._fh.close()

    def __enter__(self) -> "Ledger":
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()

    # ------------------------------------------------------------------
    # 写入
    # ------------------------------------------------------------------
    def _write_locked(self, core: dict[str, Any]) -> dict[str, Any]:
        core = dict(core)
        core["ledger_index"] = len(self.records)
        core["prev_hash"] = self.head_hash
        record_hash = digest_obj(core)
        rec = {**core, "record_hash": record_hash}
        self._fh.write(json.dumps(rec, ensure_ascii=False, sort_keys=True) + "\n")
        self._fh.flush()
        os.fsync(self._fh.fileno())
        self.records.append(rec)
        return rec

    def submit(
        self,
        envelope: dict[str, Any],
        kind: str,
        *,
        idem_key: str | None = None,
        thread_name: str | None = None,
    ) -> CommitResult:
        """提交一个已签署信封。同号异摘要时落证据并抛 EquivocationError。"""
        content_digest = envelope_digest(envelope)
        issuer = envelope.get("kid")
        serial_value = envelope.get("payload", {}).get("serial")
        serial = None if serial_value is None else str(serial_value)
        tname = thread_name or threading.current_thread().name

        with self._lock:
            # 1) 幂等键优先
            if idem_key is not None and idem_key in self._idem:
                idx = self._idem[idem_key]
                old = self.records[idx]
                if old["content_digest"] == content_digest:
                    return self._result(old, duplicated=True)
                raise IdempotencyKeyConflict(
                    f"幂等键 {idem_key} 已绑定不同内容",
                    idem_key=idem_key,
                    existing_index=idx,
                )

            seq_key = (issuer, serial) if issuer is not None and serial is not None else None

            # 2) 同序号判定
            if seq_key is not None and seq_key in self._seq:
                entry = self._seq[seq_key]

                # 未发生冲突且摘要是原件：同信封重放，幂等返回原记录
                if (
                    not entry["frozen"]
                    and entry.get("index") is not None
                    and content_digest == entry.get("digest")
                ):
                    old = self.records[entry["index"]]
                    if idem_key is not None:
                        self._idem[idem_key] = old["ledger_index"]
                    return self._result(old, duplicated=True)

                # 其余情况 = 异摘要，或该序号已因 equivocation 冻结。
                # 新摘要才追加证据；已知冲突摘要直接复用最近证据。
                if content_digest not in entry["digests"]:
                    evidence = self._persist_equivocation_locked(
                        issuer=issuer,  # type: ignore[arg-type]
                        serial=serial,  # type: ignore[arg-type]
                        first_record=(
                            self.records[entry["index"]]
                            if entry.get("index") is not None
                            else None
                        ),
                        first_digest=(
                            entry.get("digest")
                            or sorted(entry["digests"])[0]
                        ),
                        conflicting_envelope=envelope,
                        conflicting_digest=content_digest,
                        thread_name=tname,
                    )
                    entry["evidence"].append(evidence["ledger_index"])
                entry["frozen"] = True
                entry["digests"].add(content_digest)
                latest_evidence_idx = entry["evidence"][-1]
                raise EquivocationError(
                    f"检测到 {issuer} 的序号 {serial} 携带不同摘要，已冻结并留证",
                    evidence=self.records[latest_evidence_idx]["envelope"]["payload"],
                )

            # 3) 正常提交
            rec = self._write_locked(
                {
                    "kind": kind,
                    "idem_key": idem_key,
                    "issuer": issuer,
                    "serial": serial,
                    "content_digest": content_digest,
                    "committed_by_thread": tname,
                    "envelope": envelope,
                }
            )
            if idem_key is not None:
                self._idem[idem_key] = rec["ledger_index"]
            if seq_key is not None:
                self._seq[seq_key] = {
                    "index": rec["ledger_index"],
                    "digest": content_digest,
                    "frozen": False,
                    "digests": {content_digest},
                    "evidence": [],
                }
            return self._result(rec, duplicated=False)

    def _persist_equivocation_locked(
        self,
        *,
        issuer: str,
        serial: str,
        first_record: dict[str, Any] | None,
        first_digest: str,
        conflicting_envelope: dict[str, Any],
        conflicting_digest: str,
        thread_name: str,
    ) -> dict[str, Any]:
        evidence_payload = {
            "typ": "equivocation",
            "issuer": issuer,
            "serial": serial,
            "digests": sorted({first_digest, conflicting_digest}),
            "first_ledger_index": (
                first_record["ledger_index"] if first_record else None
            ),
            "first_envelope": first_record["envelope"] if first_record else None,
            "conflicting_envelope": conflicting_envelope,
            "detected_by": NOTARY_ID,
        }
        signed = sign(evidence_payload, NOTARY_ID, self.keyring)
        return self._write_locked(
            {
                "kind": "equivocation",
                "idem_key": None,
                "issuer": NOTARY_ID,
                "serial": f"eq-{issuer}-{serial}",
                "content_digest": envelope_digest(signed),
                "committed_by_thread": thread_name,
                "envelope": signed,
            }
        )

    @staticmethod
    def _result(rec: dict[str, Any], *, duplicated: bool) -> CommitResult:
        receipt = {
            "ledger_index": rec["ledger_index"],
            "record_hash": rec["record_hash"],
            "content_digest": rec["content_digest"],
            "persisted_fsync": True,
        }
        return CommitResult(
            index=rec["ledger_index"],
            record_hash=rec["record_hash"],
            duplicated=duplicated,
            receipt=receipt,
            record=rec,
        )

    # ------------------------------------------------------------------
    # 供引擎/报告使用
    # ------------------------------------------------------------------
    def events_for_engine(self) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        for rec in self.records:
            out.append(
                {
                    "kind": rec["kind"],
                    "envelope": rec["envelope"],
                    "ledger_index": rec["ledger_index"],
                    "committed_by_thread": rec.get("committed_by_thread"),
                }
            )
        return out

    def is_frozen(self, issuer: str, serial: Any) -> bool:
        entry = self._seq.get((issuer, str(serial)))
        return bool(entry and entry["frozen"])

    def counts(self) -> dict[str, int]:
        by_kind: dict[str, int] = {}
        for r in self.records:
            by_kind[r["kind"]] = by_kind.get(r["kind"], 0) + 1
        return {"total": len(self.records), **by_kind}


def reopen_verify(path: str | Path, keyring: Keyring | None = None) -> Ledger:
    """从磁盘重开账本并校验哈希链。"""
    led = Ledger(path, keyring)
    if not led.verify_hash_chain():
        raise LedgerError("重开后哈希链校验失败")
    return led
