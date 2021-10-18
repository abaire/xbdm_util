"""Models responses to Remote Debugging and Control Protocol commands."""
import logging

logger = logging.getLogger(__name__)


class RDCPResponse:
    """Models a Remote Debugging and Control Protocol response."""

    TERMINATOR = b"\r\n"
    MULTILINE_TERMINATOR = b"\r\n.\r\n"
    STR_BODY_CUTOFF = 64

    STATUS_OK = 200
    STATUS_CONNECTED = 201
    STATUS_MULTILINE_RESPONSE = 202
    STATUS_BINARY_RESPONSE = 203

    STATUS_CODES = {
        0: "INVALID",
        STATUS_OK: "OK",
        STATUS_CONNECTED: "connected",
        STATUS_MULTILINE_RESPONSE: "multiline response follows",
        STATUS_BINARY_RESPONSE: "binary response follows",
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
        self.message = bytes()
        self.data = []

    def __str__(self):
        size = len(self.data)
        if self.message:
            message = self.message.decode("utf-8")
        else:
            message = self.STATUS_CODES.get(self.status, "??INVALID??")

        ret = f"RDCPResponse::{self.status}:{message} [{size}]"
        if size:
            ret += " "
            for i in range(0, min(size, self.STR_BODY_CUTOFF - 3)):
                ret += chr(self.data[i])

            if size > self.STR_BODY_CUTOFF - 3:
                ret += "..."

        return ret

    def parse(self, buffer: bytes):
        terminator = buffer.find(self.TERMINATOR)
        terminator_len = len(self.TERMINATOR)
        if terminator < 0:
            return 0

        if buffer[3] != ord("-"):
            logger.warning(f"Received non-RDCP packet {buffer}: {buffer[3]} != '-'")
            return -1

        status = buffer[:3]
        self.status = int(status)

        if self.status == self.STATUS_MULTILINE_RESPONSE:
            body_start = terminator + terminator_len
            terminator = buffer.find(self.MULTILINE_TERMINATOR)
            if terminator < 0:
                return 0

            self.data = buffer[body_start:terminator]
            self.message = buffer[4 : body_start - terminator_len]
            terminator_len = len(self.MULTILINE_TERMINATOR)
        elif self.status == self.STATUS_BINARY_RESPONSE:
            logger.error("TODO: IMPLEMENT BINARY RESPONSE PARSING")

        self.data = buffer[4:terminator]
        return terminator + terminator_len
