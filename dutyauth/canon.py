"""规范化序列化、内容摘要与 HMAC-SHA256 签署。

合成环境用对称 HMAC 充当“控制根签署”：每个控制根/节点持有一把由标签
确定性派生的密钥。离线判定方持有全部合成密钥，因此可以独立验签。
"""

from __future__ import annotations

import hashlib
import hmac
import json
from typing import Any

SYNTH_KEY_PREFIX = "dutyauth-synthetic-control-key/v1/"


def canonical_dumps(obj: Any) -> str:
    """跨进程/跨平台稳定的规范化 JSON 文本。"""
    return json.dumps(
        obj,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )


def canonical_bytes(obj: Any) -> bytes:
    return canonical_dumps(obj).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def digest_obj(obj: Any) -> str:
    """任意可 JSON 化对象的规范化 SHA-256。"""
    return sha256_hex(canonical_bytes(obj))


def derive_node_key(node_id: str) -> bytes:
    """为合成节点确定性派生 32 字节密钥（仅用于本地合成数据）。"""
    return hashlib.sha256((SYNTH_KEY_PREFIX + node_id).encode("utf-8")).digest()


class Keyring:
    """节点/控制根密钥表。未显式登记的节点按确定性派生密钥解析。"""

    def __init__(self, root_keys: dict[str, bytes] | None = None) -> None:
        self._root_keys = dict(root_keys or {})

    def key_for(self, kid: str) -> bytes:
        if kid in self._root_keys:
            return self._root_keys[kid]
        return derive_node_key(kid)

    def add_root(self, root_id: str, key: bytes) -> None:
        self._root_keys[root_id] = key


def sign(payload: dict[str, Any], signer: str, keyring: Keyring) -> dict[str, Any]:
    """对 payload 生成签署信封（不修改原对象）。"""
    body = canonical_bytes(payload)
    sig = hmac.new(keyring.key_for(signer), body, hashlib.sha256).hexdigest()
    return {"alg": "HS256", "kid": signer, "payload": payload, "sig": sig}


def signing_bytes(envelope: dict[str, Any]) -> bytes:
    return canonical_bytes(envelope["payload"])


def verify(envelope: dict[str, Any], keyring: Keyring) -> bool:
    """恒定时间验签；信封格式错误一律返回 False。"""
    try:
        if envelope.get("alg") != "HS256":
            return False
        kid = envelope["kid"]
        expected = hmac.new(
            keyring.key_for(kid), signing_bytes(envelope), hashlib.sha256
        ).hexdigest()
        return hmac.compare_digest(expected, envelope.get("sig", ""))
    except (KeyError, TypeError, ValueError):
        return False


def envelope_digest(envelope: dict[str, Any]) -> str:
    """整个签署信封的摘要，用作账本去重/同号比对的内容指纹。"""
    return digest_obj(envelope)
