from __future__ import annotations

import re
from typing import Iterable
from typing import Optional

from .util import match_hex


class Module:
    """Models an XBOX module."""

    def __init__(
        self,
        name: str,
        base_address: int,
        size: int,
        checksum: int,
        timestamp: int,
        attributes: Optional[Iterable[str]] = None,
    ):
        self.name = name
        self.base_address = base_address
        self.size = size
        self.checksum = checksum
        self.timestamp = timestamp
        self.attributes = attributes

    def __str__(self):
        if self.attributes:
            attribute_str = " " + " ".join(sorted(self.attributes))
        else:
            attribute_str = ""

        return "%s: %s Mem: 0x%X - 0x%X (%d) Check: 0x%08X%s" % (
            self.__class__.__name__,
            self.name,
            self.base_address,
            self.base_address + self.size,
            self.size,
            self.checksum,
            attribute_str,
        )

    # 'name="XShell_new.exe" base=0x00010bc0 size=0x001c5880 check=0x00000000 timestamp=0x00000000 tls xbe'
    _RE = re.compile(
        r"name=\"([^\"]+)\"\s+"
        + r"\s+".join([match_hex(x) for x in ["base", "size", "check", "timestamp"]])
        + r"\s*(.*)"
    )

    @classmethod
    def parse(cls, message: str) -> Optional[Module]:
        match = cls._RE.match(message)
        if not match:
            return None

        attributes = None
        if match.group(6):
            attributes = match.group(6).split(" ")

        return cls(
            name=match.group(1),
            base_address=int(match.group(2), 0),
            size=int(match.group(3), 0),
            checksum=int(match.group(4), 0),
            timestamp=int(match.group(5), 0),
            attributes=attributes,
        )
