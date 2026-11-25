"""零依赖手工 SVG：证书小图、水位穷举网格、重算范围对比。

配色采用无障碍、克制的分类色（绿=允许，琥珀=根不足/等待，
灰=空水位，紫/红=撤回或拒绝），不依赖网络字体或脚本。
"""

from __future__ import annotations

from html import escape
from typing import Any

COLORS = {
    "allow": ("#1a7f37", "#dafbe1", "#116329"),
    "pending": ("#9a6700", "#fff8c5", "#7d4e00"),
    "empty": ("#57606a", "#eaeef2", "#424a53"),
    "revoked": ("#8250df", "#fbefff", "#6639ba"),
    "deny": ("#cf222e", "#ffebe9", "#a40e26"),
    "ink": "#1f2328",
    "muted": "#57606a",
    "blue": "#2563eb",
    "teal": "#0d9488",
    "red": "#cf222e",
}

SHORT_CN = {
    "OK": "允许",
    "NO_APPROVAL": "无批准",
    "INSUFFICIENT_ROOTS": "独立根不足",
    "REVOKED": "已撤回",
    "SEAL_MISMATCH": "摘要不符",
    "TERM_EXPIRED": "任期已过",
    "TERM_NOT_STARTED": "任期未始",
    "SCOPE_DENIED": "超出范围",
    "SCOPE_ORG_MISMATCH": "组织不符",
    "EQUIVOCATION": "同号异摘要",
    "BAD_APPROVAL_SIGNATURE": "签署无效",
}


def category(code: str, allowed: bool) -> str:
    if allowed:
        return "allow"
    if code == "NO_APPROVAL":
        return "empty"
    if code == "INSUFFICIENT_ROOTS":
        return "pending"
    if code == "REVOKED":
        return "revoked"
    return "deny"


def _e(s: Any) -> str:
    return escape(str(s), quote=True)


# ----------------------------------------------------------------------
# 证书小图
# ----------------------------------------------------------------------
def cert_graph_svg() -> str:
    defs = """
    <defs>
      <marker id="arrow-blue" markerWidth="9" markerHeight="9" refX="8" refY="4.5" orient="auto">
        <path d="M0,0 L9,4.5 L0,9 z" fill="#2563eb"/>
      </marker>
      <marker id="arrow-teal" markerWidth="9" markerHeight="9" refX="8" refY="4.5" orient="auto">
        <path d="M0,0 L9,4.5 L0,9 z" fill="#0d9488"/>
      </marker>
      <marker id="arrow-gray" markerWidth="9" markerHeight="9" refX="8" refY="4.5" orient="auto">
        <path d="M0,0 L9,4.5 L0,9 z" fill="#8c959f"/>
      </marker>
      <marker id="arrow-red" markerWidth="9" markerHeight="9" refX="8" refY="4.5" orient="auto">
        <path d="M0,0 L9,4.5 L0,9 z" fill="#cf222e"/>
      </marker>
    </defs>"""

    def node(x, y, w, h, label, sub, fill="#ffffff", stroke="#8c959f",
             label_size=13) -> str:
        sub_t = (
            f'<text x="{x + w/2}" y="{y + h - 9}" text-anchor="middle" '
            f'font-size="10" fill="#57606a">{_e(sub)}</text>'
            if sub else ""
        )
        label_y = y + h / 2 + (4 if sub else 5)
        return (
            f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="9" '
            f'fill="{fill}" stroke="{stroke}" stroke-width="1.6"/>'
            f'<text x="{x + w/2}" y="{label_y}" text-anchor="middle" '
            f'font-size="{label_size}" font-weight="700" fill="#1f2328">{_e(label)}</text>'
            f"{sub_t}"
        )

    def edge(d, color, marker, label, lx, ly, dashed=False) -> str:
        dash = ' stroke-dasharray="6 4"' if dashed else ""
        return (
            f'<path d="{d}" fill="none" stroke="{color}" stroke-width="1.8" '
            f'marker-end="url(#{marker})"{dash}/>'
            f'<rect x="{lx - 34}" y="{ly - 11}" width="68" height="16" rx="8" '
            f'fill="#ffffff" opacity="0.92"/>'
            f'<text x="{lx}" y="{ly + 1}" text-anchor="middle" font-size="9.5" '
            f'fill="{color}" font-weight="700">{_e(label)}</text>'
        )

    parts = [
        '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 980 400" '
        'font-family="Segoe UI, Microsoft YaHei, sans-serif" role="img" '
        'aria-label="最小证书图：菱形同源双链与独立第二根">',
        defs,
        '<rect x="0" y="0" width="980" height="400" fill="#fbfcfd"/>',
        '<text x="20" y="26" font-size="15" font-weight="800" fill="#1f2328">'
        '最小证书图：R1 菱形双链同源于 u-ops（计 1 票），R2 独立（计第 2 票）</text>',
    ]

    # 边（先画边，节点覆盖端点）
    parts.append(edge("M190,82 L248,80", COLORS["blue"], "arrow-blue",
                      "C1 · w≥2", 219, 70))
    parts.append(edge("M370,72 C400,60 410,48 438,40", COLORS["blue"],
                      "arrow-blue", "C2 · w≥3", 404, 48))
    parts.append(edge("M370,90 C402,104 412,118 438,126", COLORS["blue"],
                      "arrow-blue", "C4 · w≥5", 405, 112))
    parts.append(edge("M550,38 C590,60 596,140 618,168", COLORS["blue"],
                      "arrow-blue", "C3 · w≥4", 600, 92))
    parts.append(edge("M550,128 C585,140 596,166 618,176", COLORS["blue"],
                      "arrow-blue", "C5 · w≥6", 596, 158))
    parts.append(edge("M190,292 L248,292", COLORS["teal"], "arrow-teal",
                      "C6 · w≥7", 219, 282))
    parts.append(edge("M370,292 C470,286 560,236 636,206", COLORS["teal"],
                      "arrow-teal", "C7 · w≥8", 520, 262))
    # LEADER -> AP 签署
    parts.append(edge("M750,182 L808,182", COLORS["muted"], "arrow-gray",
                      "签署", 779, 172))
    # U -> AP 撤回（底部绕行）
    parts.append(
        edge(
            "M262,100 C226,132 224,190 224,250 L224,366 L884,366 L884,208",
            COLORS["red"], "arrow-red", "REV · w≥9", 556, 356, dashed=True,
        )
    )

    # 节点
    parts.append(node(40, 60, 150, 44, "root-duty", "独立控制根 R1",
                      fill="#eff6ff", stroke=COLORS["blue"]))
    parts.append(node(40, 270, 150, 44, "root-resource", "独立控制根 R2",
                      fill="#f0fdfa", stroke=COLORS["teal"]))
    parts.append(node(250, 60, 120, 40, "u-ops", "共同上游",
                      fill="#eff6ff", stroke=COLORS["blue"]))
    parts.append(node(440, 20, 110, 36, "m-lead-1", None))
    parts.append(node(440, 110, 110, 36, "m-lead-2", None))
    parts.append(node(250, 272, 120, 40, "n-res", None,
                      fill="#f0fdfa", stroke=COLORS["teal"]))
    parts.append(node(620, 160, 130, 44, "leader-lin", "批准签署人",
                      fill="#fff8c5", stroke="#d4a72c"))
    parts.append(node(810, 160, 150, 44, "AP-SMALL", "授权记录(绑摘要)",
                      fill="#f6f8fa", stroke="#57606a"))

    parts.append("</svg>")
    return "".join(parts)


# ----------------------------------------------------------------------
# 水位穷举网格
# ----------------------------------------------------------------------
def watermark_grid_svg(rows: list[dict[str, Any]]) -> str:
    card_w, card_h, gap = 112, 118, 8
    x0, y0 = 16, 46
    cols = len(rows)
    width = x0 * 2 + cols * card_w + (cols - 1) * gap
    height = y0 + card_h + 24

    p = [
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {width} {height}" '
        f'width="{width}" height="{height}" font-family="Segoe UI, Microsoft YaHei, sans-serif" '
        'role="img" aria-label="每个水位的穷举判定结果">',
        f'<rect width="{width}" height="{height}" fill="#ffffff"/>',
        '<text x="16" y="26" font-size="15" font-weight="800" fill="#1f2328">'
        "水位穷举：w = 可见事件数（0 为空水位，w=9 撤回生效）</text>",
    ]

    for i, r in enumerate(rows):
        x = x0 + i * (card_w + gap)
        cat = category(r["code"], r["allowed"])
        strong, bg, dark = COLORS[cat]
        w = r["watermark"]
        p.append(
            f'<rect x="{x}" y="{y0}" width="{card_w}" height="{card_h}" rx="10" '
            f'fill="{bg}" stroke="{strong}" stroke-width="1.4"/>'
            f'<rect x="{x}" y="{y0}" width="{card_w}" height="6" rx="3" fill="{strong}"/>'
            f'<text x="{x + card_w/2}" y="{y0 + 26}" text-anchor="middle" '
            f'font-size="13" font-weight="800" fill="{COLORS["ink"]}">w={w}</text>'
            f'<text x="{x + card_w/2}" y="{y0 + 50}" text-anchor="middle" '
            f'font-size="15" font-weight="800" fill="{dark}">'
            f'{"✓ 允许" if r["allowed"] else "✕ 拒绝"}</text>'
            f'<text x="{x + card_w/2}" y="{y0 + 72}" text-anchor="middle" '
            f'font-size="10.5" font-weight="700" fill="{dark}">'
            f'{_e(SHORT_CN.get(r["code"], r["code"]))}</text>'
            f'<text x="{x + card_w/2}" y="{y0 + 92}" text-anchor="middle" '
            f'font-size="9.5" fill="{COLORS["muted"]}">独立根 {r["independent_roots"]}/2'
            f' · 有效链 {r["eligible_chains"]}</text>'
        )
        if r.get("collapse_notes"):
            p.append(
                f'<circle cx="{x + card_w - 12}" cy="{y0 + 14}" r="7" '
                f'fill="{COLORS["pending"][0]}"/>'
                f'<text x="{x + card_w - 12}" y="{y0 + 17.5}" text-anchor="middle" '
                f'font-size="9" font-weight="800" fill="#fff">1</text>'
            )

    p.append("</svg>")
    return "".join(p)


# ----------------------------------------------------------------------
# 重算范围对比条
# ----------------------------------------------------------------------
def scope_bar_svg(scale: dict[str, Any]) -> str:
    scoped = scale["scoped_recompute"]["records_actually_read"]
    full = scale["full_recompute"]["records_actually_read"]
    w = 720
    row_h = 46
    h = 150
    max_bar_w = 460
    sx = 150

    def bar(y, value, color, label):
        bw = max(2.0, max_bar_w * value / full)
        return (
            f'<text x="140" y="{y + 16}" text-anchor="end" font-size="12" '
            f'font-weight="700" fill="#1f2328">{label}</text>'
            f'<rect x="{sx}" y="{y}" width="{bw:.1f}" height="24" rx="5" fill="{color}"/>'
            f'<text x="{sx + bw + 8}" y="{y + 16}" font-size="12" font-weight="800" '
            f'fill="#1f2328">{value:,} 条</text>'
        )

    ratio = scale["scope_ratio_vs_full"]
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {w} {h}" '
        f'font-family="Segoe UI, Microsoft YaHei, sans-serif" role="img" '
        f'aria-label="增量重算与全量重算实际读取条数对比">'
        f'<rect width="{w}" height="{h}" fill="#ffffff"/>'
        f'<text x="16" y="26" font-size="15" font-weight="800" fill="#1f2328">'
        f'重算范围（实际读取条数）：单组织增量仅全量的 {ratio:.2%}</text>'
        + bar(48, scoped, COLORS["teal"], "受影响组织增量")
        + bar(92, full, COLORS["muted"], "全量重算")
        + f'<text x="16" y="138" font-size="11" fill="#57606a">'
        f'增量路径读取 {scoped} 条（=该组织 3000+1），其他组织读取 0 条；'
        f'全量读取 {full:,} 条；两者结果逐组织完全一致。</text>'
        f"</svg>"
    )
