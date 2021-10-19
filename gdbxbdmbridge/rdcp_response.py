"""Models responses to Remote Debugging and Control Protocol commands."""
import logging

logger = logging.getLogger(__name__)


def parse_array(data: bytes) -> [bytes]:
    """Processes data as a list of lines."""
    if not data:
        return []

    return data.split(RDCPResponse.TERMINATOR)


def parse_data_map_array(data: bytes) -> [{bytes, bytes}]:
    """Process data as a \r\n delimited list of key=value maps."""
    maps = parse_array(data)
    return [parse_data_map(m) for m in maps]


def parse_data_map(data: bytes) -> {bytes, bytes}:
    """Processes data as a space-delimited list of key=value pairs."""
    if not data:
        return {}

    buffer = data.replace(RDCPResponse.TERMINATOR, b" ").strip()

    # Temporarily replace spaces between quotes with non-printable
    # characters (XBDM should not send non-printable chars inside quotes)
    # they will be restored
    quoted_sections = buffer.split(b'"')
    buffer = bytearray()
    ESCAPED_SPACE = bytes([1])
    for i, section in enumerate(quoted_sections):
        # Even sections are quoted
        if (i & 0x01) == 1:
            section = section.replace(b" ", ESCAPED_SPACE)
        buffer.extend(section)

    ret = {}
    items = buffer.split(b" ")
    for item in items:
        keyval = item.split(b"=")
        if len(keyval) == 2:
            key, value = keyval
            ret[bytes(key)] = bytes(value).replace(ESCAPED_SPACE, b" ")
        else:
            # The value is a flag, treat it as a True
            ret[bytes(keyval[0])] = bytes("1", "utf-8")
    return ret


def get_utf_property(property_map: {bytes: bytes}, key: bytes, default=None) -> str:
    """Returns the value of the given key as a UTF-8 string."""
    val = property_map.get(key, default)
    if not val:
        return ""
    ret = val.decode("utf-8")
    if ret[0] == '"':
        ret = ret[1:-1]
    return ret


def get_int_property(property_map: {bytes: bytes}, key: bytes, default=0) -> int:
    """Returns the value of the given key as an integer."""
    return int(get_utf_property(property_map, key, bytes(f"{default}", "utf-8")), 16)


def get_qword_property(
    property_map: {bytes: bytes}, key_low: bytes, key_high: bytes, default=0
) -> int:
    """Returns the combination of the given keys as a 64-bit integer."""

    low = get_int_property(property_map, key_low, default & 0xFFFFFFFF)
    high = get_int_property(property_map, key_high, (default >> 32) & 0xFFFFFFFF)

    return low + (high << 32)


def get_bool_property(property_map: {bytes: bytes}, key: bytes, default=False) -> bool:
    """Returns the value of the given key as a bool."""
    return get_int_property(property_map, key, 1 if default else 0) != 0


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
        self.data = bytes()

    def __str__(self):
        size = len(self.data)
        if self.message:
            message = self.message.decode("utf-8")
        else:
            message = self.STATUS_CODES.get(self.status, "??INVALID??")

        ret = f"{self.__class__.__name__}::{self.status}:{message} [{size}]"
        if size:
            ret += " "
            for i in range(0, min(size, self.STR_BODY_CUTOFF - 3)):
                ret += chr(self.data[i])

            if size > self.STR_BODY_CUTOFF - 3:
                ret += "..."

        return ret

    def debug_log(self):
        logger.debug(f"{self.__class__.__name__}::{self.status}\n{self.data}\n\n")

    def parse_multiline(self) -> [bytes]:
        """Processes self.data as a list of lines."""
        return parse_array(self.data)

    def parse_hex_data(self) -> (str, bytearray):
        """Processes self.data as a chunk of hex values."""
        lines = self.parse_multiline()
        printable_value = (b"".join(lines)).decode("utf-8")
        return printable_value, bytearray.fromhex(printable_value)

    def parse_data_map_array(self) -> [bytes, bytes]:
        """Process self.data as a \r\n delimited list of key=value maps."""
        return parse_data_map_array(self.data)

    def parse_data_map(self) -> {bytes, bytes}:
        """Processes self.data as a space-delimited list of key=value pairs."""
        buffer = self.data.replace(self.TERMINATOR, b" ").strip()
        return parse_data_map(buffer)

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
            self.message = buffer[5 : body_start - terminator_len]
            terminator_len = len(self.MULTILINE_TERMINATOR)
        elif self.status == self.STATUS_BINARY_RESPONSE:
            logger.error("TODO: IMPLEMENT BINARY RESPONSE PARSING")
        else:
            self.data = buffer[5:terminator]

        return terminator + terminator_len
