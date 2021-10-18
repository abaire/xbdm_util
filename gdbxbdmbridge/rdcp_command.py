"""Provides utilities in support of Remote Debugging and Control Protocol."""
import ipaddress
import logging
from typing import Callable

from . import rdcp_response

logger = logging.getLogger(__name__)


class RDCPCommand:
    """Models a Remote Debugging and Control Protocol command."""

    TERMINATOR = b"\r\n"
    STR_BODY_CUTOFF = 16

    COMMANDS = {
        "adminpw",
        "altaddr",  #  addr=0x0a000210
        "authuser",
        # "boxid",  # Can only be executed if security is enabled.
        "break",
        "bye",
        "capcontrol",
        "continue",
        "crashdump",
        "d3dopcode",
        "dbgname",
        "dbgoptions",
        "debugger",
        "debugmode",
        "dedicate",
        "deftitle",
        "delete",
        "dirlist",
        "dmversion",
        "drivefreespace",
        "drivelist",
        "dvdblk",
        "dvdperf",
        "fileeof",
        "flash",
        "fmtfat",
        "funccall",
        "getcontext",
        "getd3dstate",
        "getextcontext",
        "getfile",
        "getfileattributes",
        "getgamma",
        "getmem",
        "getmem2",
        "getpalette",
        "getpid",
        "getsum",
        "getsurf",
        "getuserpriv",
        "getutildrvinfo",
        "go",
        "gpucount",
        "halt",
        "irtsweep",
        "isbreak",
        "isdebugger",
        "isstopped",
        "kd",
        "keyxchg",
        "lockmode",
        "lop",
        "magicboot",
        "memtrack",
        "mkdir",
        "mmglobal",
        "modlong",
        "modsections",
        "modules",
        "nostopon",
        "notify",
        "notifyat",
        "pbsnap",
        "pclist",
        "pdbinfo",
        "pssnap",
        "querypc",
        "reboot",
        "rename",
        "resume",
        "screenshot",
        "sendfile",
        "servname",
        "setconfig",
        "setcontext",
        "setfileattributes",
        "setsystime",
        "setuserpriv",
        "signcontent",
        "stop",
        "stopon",
        "suspend",
        "sysfileupd",
        "systime",  # high=0x1d7c3df low=0xb7852a80
        "threadinfo",
        "threads",
        "title",
        "user",
        "userlist",
        "vssnap",
        "walkmem",
        "writefile",
        "xbeinfo",
        "xtlinfo",
    }

    def __init__(
        self,
        command: str,
        body: bytes = None,
        response_handler: Callable[[rdcp_response.RDCPResponse], bool] = None,
    ):
        self.command = command.lower()
        self.body = body
        self._response_handler = response_handler

        # if self.command not in self.COMMANDS:
        #     logger.error(f"Invalid command {command}")
        #     self.command = None
        #     return

    def __str__(self):
        ret = f"{self.__class__.__name__}({self.command})"

        size = 0 if not self.body else len(self.body)
        if size:
            ret += " '"
            for i in range(0, min(size, self.STR_BODY_CUTOFF - 3)):
                ret += chr(self.body[i])

            if size > self.STR_BODY_CUTOFF - 3:
                ret += "..."
            ret += "'"

        return ret

    def serialize(self) -> bytes:
        if not self.command:
            return bytes()

        ret = bytearray(self.command, "utf-8")

        if self.body:
            ret += self.body

        ret += self.TERMINATOR

        return ret

    def process_response(self, response: rdcp_response.RDCPResponse) -> bool:
        if not self._response_handler:
            return True
        return self._response_handler(response)


class _ProcessedCommand(RDCPCommand):
    """Processes the response to the command in some command-specific way."""

    def __init__(self, command, response_class, handler=None, **kw):
        def process_response(response: rdcp_response.RDCPResponse) -> bool:
            unpacked = response_class(response)
            if not self._processed_response_handler:
                return False
            return self._processed_response_handler(unpacked)

        super().__init__(command, response_handler=process_response, **kw)
        self._processed_response_handler = handler


class _ProcessedResponse:
    def __init__(self, response: rdcp_response.RDCPResponse):
        self._status = response.status
        self._message = response.message

    @property
    def ok(self):
        return self._status == rdcp_response.RDCPResponse.STATUS_OK

    @property
    def _body_str(self) -> str:
        return ""

    def __str__(self):
        if self._message:
            message = self._message.decode("utf-8")
        else:
            message = rdcp_response.RDCPResponse.STATUS_CODES.get(
                self._status, "??INVALID??"
            )

        ret = f"{self.__class__.__qualname__}::{self._status}:{message}{self._body_str}"
        return ret


class AltAddr(_ProcessedCommand):
    """Returns the Game Configuration IP."""

    class Response(_ProcessedResponse):
        def __init__(self, response: rdcp_response.RDCPResponse):
            super().__init__(response)

            if not self.ok:
                self.alt_ip = None
                return

            entries = response.parse_data_map()
            ip = rdcp_response.get_int_property(entries, b"addr")

            self.alt_ip = str(ipaddress.ip_address(ip))

        @property
        def _body_str(self) -> str:
            return f" {self.alt_ip}"

    def __init__(self, handler=None):
        super().__init__("altaddr", response_class=self.Response, handler=handler)


class Bye(_ProcessedCommand):
    """Closes the connection gracefully."""

    class Response(_ProcessedResponse):
        pass

    def __init__(self, handler=None):
        super().__init__("bye", response_class=self.Response, handler=handler)


class DriveList(_ProcessedCommand):
    """Lists mounted drives on the XBOX."""

    class Response(_ProcessedResponse):
        def __init__(self, response: rdcp_response.RDCPResponse):
            super().__init__(response)

            if not self.ok:
                self.drives = None
            else:
                self.drives = sorted([chr(x) for x in response.data])

        @property
        def _body_str(self) -> str:
            return f" {self.drives}"

    def __init__(self, handler=None):
        super().__init__("drivelist", response_class=self.Response, handler=handler)


class DriveFreeSpace(_ProcessedCommand):
    """Returns the amount of free space on a drive."""

    class Response(_ProcessedResponse):
        def __init__(self, response: rdcp_response.RDCPResponse):
            super().__init__(response)

            self.free_to_caller = 0
            self.total_bytes = 0
            self.total_free_bytes = 0

            if not self.ok:
                return

            entries = response.parse_data_map()
            self.free_to_caller = rdcp_response.get_int_property(
                entries, b"freetocallerlo"
            )
            self.free_to_caller += (
                rdcp_response.get_int_property(entries, b"freetocallerhi") << 32
            )

            self.total_bytes = rdcp_response.get_int_property(entries, b"totalbyteslo")
            self.total_bytes += (
                rdcp_response.get_int_property(entries, b"totalbyteshi") << 32
            )

            self.total_free_bytes = rdcp_response.get_int_property(
                entries, b"totalfreebyteslo"
            )
            self.total_free_bytes += (
                rdcp_response.get_int_property(entries, b"totalfreebyteshi") << 32
            )

        @property
        def ok(self):
            return self._status == rdcp_response.RDCPResponse.STATUS_MULTILINE_RESPONSE

        @property
        def _body_str(self) -> str:
            return f"  total: {self.total_bytes} total free: {self.total_free_bytes} free to caller: {self.free_to_caller}"

    def __init__(self, drive_letter, handler=None):
        super().__init__(
            "drivefreespace", response_class=self.Response, handler=handler
        )
        self.body = bytes(f' name="{drive_letter}:\\"', "utf-8")
