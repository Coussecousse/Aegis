"""Behavioral UEBA scoring (Gap 2): a simple, explainable anomaly signal.

Privilege (asset criticality / tier) is handled separately by the risk scorer's
criticality multiplier. This module answers a *different* question: **is this
asset behaving abnormally right now, compared to its own recent baseline?**

It is a first-level behavioral heuristic — a trailing event window plus an EWMA
baseline — not an ML engine, which keeps it explainable and POC-appropriate:

- count the asset's events in a trailing window (e.g. the last 5 minutes),
- compare that count to a learned baseline rate for the same window,
- a count well above baseline → high anomaly; at/below baseline → ~0,
- the baseline slowly follows the observed rate (EWMA), so sustained activity
  becomes the new normal and the score decays back toward 0 on its own.

All functions are pure so they are unit-tested without database dependencies or a live run.
"""

from __future__ import annotations

# Trailing activity window, in seconds (how far back "recent" looks).
DEFAULT_WINDOW_S = 300.0
# recent_count >= baseline * SPIKE_FACTOR maps to the maximum score (1.0).
DEFAULT_SPIKE_FACTOR = 3.0
# EWMA smoothing for the learned baseline (higher = adapts faster).
DEFAULT_BASELINE_ALPHA = 0.2
# Floor for the baseline so a near-idle asset is not hyper-sensitive to 1-2 events.
_MIN_BASELINE = 1.0


def prune_window(
    timestamps: list[float], now: float, window_s: float = DEFAULT_WINDOW_S
) -> list[float]:
    """Return only the timestamps falling within the trailing ``window_s``."""
    cutoff = now - window_s
    return [t for t in timestamps if t >= cutoff]


def anomaly_score(
    recent_count: int,
    baseline: float,
    *,
    spike_factor: float = DEFAULT_SPIKE_FACTOR,
) -> float:
    """Behavioral anomaly in ``[0.0, 1.0]``.

    ``0.0`` when recent activity is at or below baseline; rises linearly to
    ``1.0`` once recent activity reaches ``baseline * spike_factor``.

    Args:
        recent_count: Events observed for the asset in the trailing window.
        baseline: Learned normal event count for the same window.
        spike_factor: Multiple of baseline that counts as a full anomaly.

    Returns:
        The bounded anomaly score, rounded to 3 decimals.
    """
    base = max(baseline, _MIN_BASELINE)
    if recent_count <= base:
        return 0.0
    excess_ratio = (recent_count - base) / (base * (spike_factor - 1.0))
    return round(min(1.0, max(0.0, excess_ratio)), 3)


def update_baseline(
    baseline: float,
    recent_count: int,
    *,
    alpha: float = DEFAULT_BASELINE_ALPHA,
) -> float:
    """Fold the latest observed count into the EWMA baseline.

    Applied *after* scoring, so a spike scores high once and is then gradually
    absorbed: sustained load becomes the new normal and the score decays.
    """
    return round((1.0 - alpha) * baseline + alpha * recent_count, 3)
