from __future__ import annotations

import re
from typing import Optional

from .util import match_hex


class Section:
    """Models an XBE section."""

    def __init__(
        self, name: str, base_address: int, size: int, index: int, flags: int = 0
    ):
        self.name = name
        self.base_address = base_address
        self.size = size
        self.index = index
        self.flags = flags

    def __str__(self):
        return "%s: %s @%d Flags: 0x08%X Mem: 0x%X - 0x%X (%d)" % (
            self.__class__.__name__,
            self.name,
            self.size,
            self.flags,
            self.base_address,
            self.base_address + self.size,
            self.size,
        )

    # 'name="XONLINE" base=0x00011000 size=0x00054eec index=0 flags=1'
    _RE = re.compile(
        r"name=\"([^\"]+)\"\s+"
        + r"\s+".join([match_hex(x) for x in ["base", "size", "index", "flags"]])
    )

    @classmethod
    def parse(cls, message: str) -> Optional[Section]:
        match = cls._RE.match(message)
        if not match:
            return None

        return cls(
            name=match.group(1),
            base_address=int(match.group(2), 0),
            size=int(match.group(3), 0),
            index=int(match.group(4), 0),
            flags=int(match.group(5), 0),
        )
