"""合成值班名单的离线授权判定包（仅 Python 3.12 标准库）。

模块划分：

- canon:     规范化 JSON、SHA-256 摘要、HMAC-SHA256 签署/验签
- seal:      工作区封存内容的实际目录摘要
- scope:     任期与资源范围（含委派收窄判定）
- certgraph: 证书 DAG、上游根溯源、同源双链去重、最短独立证书
- engine:    给定水位/时刻的授权判定
- ledger:    fsync 持久化、幂等、同号异摘要 equivocation 证据账本
- concurrency: 两个真实线程 + threading.Barrier 的三类复现
- synthetic: 合成小图/名单/六万事件
- scale:     按组织分区的计量重算与全量一致性
- report:    Markdown/JSON/CSV/SVG/HTML 报告
"""

__version__ = "1.0.0"

POLICY_REQUIRED_ROOTS = 2
