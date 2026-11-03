"""Shannon entropy helpers used to flag packed or encrypted sections."""

from __future__ import annotations

import math

# A section whose byte entropy exceeds this is likely compressed or encrypted.
# 8.0 is the theoretical maximum for a byte stream; packers typically land
# above ~7.2, while normal code and data sit well below it.
PACKED_THRESHOLD = 7.2


def shannon_entropy(data: bytes) -> float:
    """Return the Shannon entropy of ``data`` in bits per byte (0.0 - 8.0)."""
    if not data:
        return 0.0
    counts = [0] * 256
    for byte in data:
        counts[byte] += 1
    length = len(data)
    entropy = 0.0
    for count in counts:
        if count:
            p = count / length
            entropy -= p * math.log2(p)
    return entropy


def is_packed(entropy: float) -> bool:
    """Return True if ``entropy`` is high enough to suggest packing."""
    return entropy >= PACKED_THRESHOLD
