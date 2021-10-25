from typing import Dict
from typing import Optional
from typing import Union


def _mod_256_checksum(data: bytes) -> int:
    if not data:
        return 0

    checksum = 0
    for byte in data:
        checksum = (checksum + byte) & 0xFF
    return checksum


class GDBPacket:
    """Models a single GDB RSP data packet."""

    PACKET_LEADER_STR = "$"
    PACKET_LEADER = bytes(PACKET_LEADER_STR, "utf-8")

    PACKET_TRAILER_STR = "#"
    PACKET_TRAILER = bytes(PACKET_TRAILER_STR, "utf-8")

    RSP_ESCAPE_CHAR_STR = "}"
    RSP_ESCAPE_CHAR = ord(RSP_ESCAPE_CHAR_STR)

    # RSP escape sequence look up table.
    _ESCAPE_MAP: Dict[str, str] = {
        RSP_ESCAPE_CHAR_STR: RSP_ESCAPE_CHAR_STR + chr(RSP_ESCAPE_CHAR ^ 0x20),
        PACKET_LEADER_STR: RSP_ESCAPE_CHAR_STR + chr(PACKET_LEADER[0] ^ 0x20),
        PACKET_TRAILER_STR: RSP_ESCAPE_CHAR_STR + chr(PACKET_TRAILER[0] ^ 0x20),
    }

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
        if not self.data:
            self.checksum = 0
            return

        self.checksum = _mod_256_checksum(self.data.encode("utf=-8"))

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

        return terminator + 3

    def serialize(self) -> bytes:
        return self._serialize()

    def _serialize(self) -> bytes:
        escaped_data = self.data or ""
        for key, value in self._ESCAPE_MAP.items():
            escaped_data = escaped_data.replace(key, value)

        return bytes(
            "%s%s%s%02x"
            % (
                self.PACKET_LEADER_STR,
                escaped_data,
                self.PACKET_TRAILER_STR,
                self.checksum,
            ),
            "utf-8",
        )


class GDBBinaryPacket(GDBPacket):
    """Models a single GDB RSP data packet with a binary message."""

    def __init__(self, binary_data: Union[bytes, bytearray]):
        super().__init__()
        self._binary_data = binary_data
        self.checksum = _mod_256_checksum(self._binary_data)
        self.checksum_ok = True

    def __str__(self):
        ret = f"{self.__class__.__name__}"
        if self.data:
            ret += f" <checksum: {'ok' if self.checksum_ok else 'bad'}> {self._binary_data.hex()}"

        return ret

    def _serialize(self) -> bytes:
        escaped_data = self._binary_data
        for key, value in self._ESCAPE_MAP.items():
            escaped_data = escaped_data.replace(
                bytes(key, "utf-8"), bytes(value, "utf-8")
            )

        checksum = bytes("%02x" % self.checksum, "utf-8")
        return self.PACKET_LEADER + escaped_data + self.PACKET_TRAILER + checksum
