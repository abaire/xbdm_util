"""Models responses to Remote Debugging and Control Protocol commands."""
import logging

logger = logging.getLogger(__name__)


class RDCPResponse:
    """Models a Remote Debugging and Control Protocol response."""

    TERMINATOR = b"\r\n"

    STATUS_OK = 200
    STATUS_CONNECTED = 201

    STATUS_CODES = {
        0: "INVALID",
        STATUS_OK: "OK",
        STATUS_CONNECTED: "connected",
        202: "multiline response follows",
        203: "binary response follows",
        204: "send binary data",
        205: "connection dedicated",
        400: "unexpected error",
        401: "max number of connections exceeded",
        402: "file not found",
        403: "no such module",
        404: "memory not mapped",
        405: "no such thread",
        406: "failed to set system time",
        407: "unknown command",
        408: "not stopped",
        409: "file must be copied",
        410: "file already exists",
        411: "directory not empty",
        412: "filename is invalid",
        413: "file cannot be created",
        414: "access denied",
        415: "no room on device",
        416: "not debuggable",
        417: "type invalid",
        418: "data not available",
        420: "box not locked",
        421: "key exchange required",
        422: "dedicated connection required",
    }

    def __init__(self):
        self.status = 0
        self.data = []

    def __str__(self):
        size = len(self.data)
        return (
            f"{self.status}:{self.STATUS_CODES.get(self.status, '??INVALID??')}[{size}]"
        )

    def parse(self, buffer: bytes):
        terminator = buffer.find(self.TERMINATOR)
        if terminator < 0:
            return 0

        if buffer[3] != ord("-"):
            logger.warning(f"Received non-RDCP packet {buffer}: {buffer[3]} != '-'")
            return -1

        status = buffer[:3]
        self.status = int(status)
        self.data = buffer[4:terminator]

        return terminator + len(self.TERMINATOR)
