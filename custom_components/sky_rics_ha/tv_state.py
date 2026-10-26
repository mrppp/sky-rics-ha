"""Pure TV-state classification, kept free of Home Assistant imports.

RICS has no state query, so panel state is estimated from a power sensor.
Thresholds are calibrated from 24h of history: the 3-5 W band is essentially
empty (3 samples in 2818), so 3 W is the off threshold and 20 W sits safely
above the network-awake band (~7 W). The band between them holds the previous
state, which absorbs the standby oscillation.
"""

from __future__ import annotations

TV_OFF_W = 3.0
TV_ON_W = 20.0
TV_DWELL_S = 60
TV_STALE_S = 120


def classify(watts: float, current):
    """Map a wattage to a candidate state; the ambiguous band holds."""
    if watts < TV_OFF_W:
        return False
    if watts > TV_ON_W:
        return True
    return current
