"""工作区封存内容的实际摘要。

摘要直接对磁盘上的实际文件字节计算，而不是采信记录里自报的值：

    seal_digest = SHA256( 对每个排序后的相对路径逐条域分隔哈希 )

授权记录绑定该摘要；判定时重新读取封存目录计算。任何文件被增删改都会
使摘要变化，从而与授权记录中绑定的摘要不符。
"""

from __future__ import annotations

import hashlib
from pathlib import Path

from .canon import sha256_hex

SEAL_VERSION = "dutyauth-seal-v1"

# 封存目录中这些后缀/文件不纳入内容摘要（清单本身不能自证）
DEFAULT_EXCLUDE_NAMES = {"seal_manifest.json"}
DEFAULT_EXCLUDE_SUFFIX = (".pyc",)


def _iter_sealed_files(root: Path):
    root = Path(root)
    for path in sorted(p for p in root.rglob("*") if p.is_file()):
        rel = path.relative_to(root)
        parts = rel.parts
        if any(part == "__pycache__" for part in parts):
            continue
        if path.name in DEFAULT_EXCLUDE_NAMES:
            continue
        if path.suffix in DEFAULT_EXCLUDE_SUFFIX:
            continue
        yield path, rel.as_posix()


def compute_seal_digest(root: str | Path) -> str:
    """对封存目录的**实际内容**计算确定性摘要。"""
    root = Path(root)
    if not root.exists() or not root.is_dir():
        raise FileNotFoundError(f"封存内容目录不存在: {root}")

    h = hashlib.sha256()
    h.update(SEAL_VERSION.encode("utf-8"))
    h.update(b"\n")
    for path, rel_posix in _iter_sealed_files(root):
        data = path.read_bytes()
        h.update(b"entry\n")
        h.update(rel_posix.encode("utf-8"))
        h.update(b"\n")
        h.update(str(len(data)).encode("ascii"))
        h.update(b"\n")
        h.update(hashlib.sha256(data).digest())
        h.update(b"\n")
    return h.hexdigest()


def build_manifest(root: str | Path) -> dict:
    """生成封存清单（含逐文件摘要与总摘要），供报告展示。"""
    root = Path(root)
    files = []
    file_count = 0
    total_bytes = 0
    for path, rel_posix in _iter_sealed_files(root):
        data = path.read_bytes()
        files.append(
            {
                "path": rel_posix,
                "bytes": len(data),
                "sha256": sha256_hex(data),
            }
        )
        file_count += 1
        total_bytes += len(data)
    return {
        "seal_version": SEAL_VERSION,
        "root": root.as_posix(),
        "file_count": file_count,
        "total_bytes": total_bytes,
        "seal_digest": compute_seal_digest(root),
        "files": files,
    }


def digest_matches(root: str | Path, expected: str) -> bool:
    try:
        return compute_seal_digest(root) == expected
    except FileNotFoundError:
        return False
