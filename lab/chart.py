"""``docs/img/timeline.png``: one chart, four labelled bars on a shared time axis."""

from __future__ import annotations

from pathlib import Path

from lab.metrics import Metrics, fmt_duration

SURFACE, INK, MUTED, GRID = "#fcfcfb", "#0b0b0b", "#52514e", "#e4e3df"
ORANGE, RED, BLUE, GRAY = "#eb6834", "#e34948", "#2a78d6", "#8a8984"


def bar_rows(m: Metrics) -> list[tuple[str, float, float, str]]:
    """(label, start, end, colour) in seconds relative to the attack start, top to bottom."""
    verified = (m.restore_verified - m.attack_start).total_seconds()
    detected = m.detection_delay_s
    return [
        ("Data at risk (RPO)", -m.rpo_s, 0.0, ORANGE),
        ("Detection delay", 0.0, detected, RED),
        ("Response + restore (RTO)", detected, verified, BLUE),
        ("Total downtime", 0.0, verified, GRAY),
    ]


def render_timeline_png(m: Metrics, path: Path) -> None:
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    rows = bar_rows(m)
    fig, ax = plt.subplots(figsize=(9, 3.8), dpi=200, facecolor=SURFACE)
    ax.set_facecolor(SURFACE)
    for index, (_label, start, end, colour) in enumerate(rows):
        y = len(rows) - 1 - index
        width = max(end - start, 0.15)  # a sliver stays visible
        ax.barh(y, width, left=start, height=0.5, color=colour, zorder=3)
        ax.text(
            max(start, end) + 0.01 * _span(rows), y, fmt_duration(end - start),
            va="center", ha="left", fontsize=9.5, color=INK, zorder=4,
        )  # fmt: skip
    ax.axvline(0, color=INK, linewidth=1.2, linestyle=(0, (4, 3)), zorder=2)
    ax.text(0, len(rows) - 0.35, " attack starts", fontsize=9, color=MUTED, va="bottom")
    ax.set_yticks(range(len(rows)), [r[0] for r in reversed(rows)], fontsize=10, color=INK)
    lo, hi = min(r[1] for r in rows), max(r[2] for r in rows)
    ax.set_xlim(lo - 0.02 * _span(rows), hi + 0.16 * _span(rows))
    ax.set_xlabel("seconds relative to the start of the attack", fontsize=9, color=MUTED)
    ax.tick_params(axis="x", colors=MUTED, labelsize=9)
    ax.tick_params(axis="y", length=0)
    ax.grid(axis="x", color=GRID, linewidth=0.8, zorder=0)
    ax.set_axisbelow(True)
    for side in ("top", "right", "left"):
        ax.spines[side].set_visible(False)
    ax.spines["bottom"].set_color(GRID)
    ax.set_title(
        "Ransomware recovery timeline (one run)", loc="left", fontsize=12, color=INK, pad=22
    )
    fig.tight_layout()
    path.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(path, facecolor=SURFACE)
    plt.close(fig)


def _span(rows: list[tuple[str, float, float, str]]) -> float:
    return (max(r[2] for r in rows) - min(r[1] for r in rows)) or 1.0
