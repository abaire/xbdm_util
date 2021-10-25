import binascii
import struct
from typing import Optional


class GDBPacket:
    PACKET_LEADER_STR = "$"
    PACKET_LEADER = bytes(PACKET_LEADER_STR, "utf-8")

    PACKET_TRAILER_STR = "#"
    PACKET_TRAILER = bytes(PACKET_TRAILER_STR, "utf-8")

    def __init__(self, data: Optional[str] = None):
        self.data: Optional[str] = data
        self.checksum: int = 0
        self.checksum_ok: bool = data is not None
        self._calculate_checksum()

    def __str__(self):
        ret = f"{self.__class__.__name__}"
        if self.data:
            ret += f" <checksum: {'ok' if self.checksum_ok else 'bad'}> {self.data}"

        return ret

    def _calculate_checksum(self):
        self.checksum = 0
        if not self.data:
            return

        for byte in self.data.encode("utf-8"):
            self.checksum = (self.checksum + byte) & 0xFF

    def parse(self, buffer: bytes) -> int:
        leader = buffer.find(self.PACKET_LEADER)
        if leader < 0:
            return 0
        body_start = leader + 1

        terminator = buffer.find(self.PACKET_TRAILER, body_start)
        if terminator < 0 or len(buffer) < terminator + 2:
            return 0

        received_checksum = int(buffer[terminator + 1 : terminator + 3], 16)

        self.data = buffer[body_start:terminator].decode("utf-8")
        self._calculate_checksum()
        self.checksum_ok = self.checksum == received_checksum

        return terminator + 2

    def serialize(self) -> bytes:
        return bytes(
            "%s%s%s%02x"
            % (
                self.PACKET_LEADER_STR,
                self.data or "",
                self.PACKET_TRAILER_STR,
                self.checksum,
            ),
            "utf-8",
        )
