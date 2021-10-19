"""Provides utilities in support of Remote Debugging and Control Protocol."""
import enum
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
        "altaddr",  #  > addr=0x0a000210
        "authuser",  # (resp=QWORD name=STRING) > 414:access denied  # Looks like "passwd" is another param maybe for an older XDK?
        # "boxid",  # Can only be executed if security is enabled.
        "capctrl",  # () > 400
        "crashdump",
        "d3dopcode",
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

    def set_handler(self, handler):
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


class _ProcessedRawBodyResponse(_ProcessedResponse):
    def __init__(self, response: rdcp_response.RDCPResponse):
        super().__init__(response)
        self._body = response.data

    @property
    def _body_str(self) -> str:
        return self._body.decode("utf-8")


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


class _Break(_ProcessedCommand):
    """Manages breakpoints."""

    class Response(_ProcessedResponse):
        pass

    def __init__(self, handler=None):
        super().__init__("break", response_class=self.Response, handler=handler)


class BreakNow(_Break):
    """Break into debugger immediately."""

    def __init__(self, handler=None):
        super().__init__(handler)
        self.body = b" now"


class BreakAtStart(_Break):
    """Break into debugger at process start."""

    def __init__(self, handler=None):
        super().__init__(handler)
        self.body = b" start"


class BreakClearAll(_Break):
    """Clears all breakpoints."""

    def __init__(self, handler=None):
        super().__init__(handler)
        self.body = b" clearall"


class BreakAtAddress(_Break):
    """Adds or clears a breakpoint at the given memory address."""

    def __init__(self, address: int, clear: bool = False, handler=None):
        super().__init__(handler)
        clear_string = "clear " if clear else ""
        self.body = bytes(f" {clear_string}addr={address}")


class _BreakRange(_Break):
    """Breaks on access to a memory range."""

    def __init__(
        self,
        access_type: str,
        address: int,
        size: int = 0,
        clear: bool = False,
        handler=None,
    ):
        super().__init__(handler)
        clear_string = "clear " if clear else ""
        size_string = f"size={size}" if not clear else ""
        self.body = bytes(f" {clear_string}{access_type}={address}{size_string}")


class BreakOnRead(_BreakRange):
    """Adds or clears a breakpoint when reading the given memory range."""

    def __init__(self, address: int, size: int = 0, clear: bool = False, handler=None):
        super().__init__("read", address, size, clear, handler)


class BreakOnWrite(_BreakRange):
    """Adds or clears a breakpoint when writing the given memory range."""

    def __init__(self, address: int, size: int = 0, clear: bool = False, handler=None):
        super().__init__("write", address, size, clear, handler)


class BreakOnExecute(_BreakRange):
    """Adds or clears a breakpoint when executing the given memory range."""

    def __init__(self, address: int, size: int = 0, clear: bool = False, handler=None):
        super().__init__("execute", address, size, clear, handler)


class Bye(_ProcessedCommand):
    """Closes the connection gracefully."""

    class Response(_ProcessedResponse):
        pass

    def __init__(self, handler=None):
        super().__init__("bye", response_class=self.Response, handler=handler)


# class Capcontrol(_ProcessedCommand):
#     """??."""
#
#     class Response(_ProcessedResponse):
#         pass
#
#     def __init__(self, handler=None):
#         super().__init__("continue", response_class=self.Response, handler=handler)
#         # params: start (name buffersize) | fastcapenabled | stop
#         thread_id_string = "0x%X" % thread_id
#         exception_string = " exception" if exception else ""
#         self.body = bytes(f" thread={thread_id_string}{exception_string}")


class Continue(_ProcessedCommand):
    """Continues execution of the given thread."""

    class Response(_ProcessedResponse):
        pass

    def __init__(self, thread_id, exception: bool = False, handler=None):
        # TODO: Document 'exception' flag behavior.
        super().__init__("continue", response_class=self.Response, handler=handler)
        thread_id_string = "0x%X" % thread_id
        exception_string = " exception" if exception else ""
        self.body = bytes(f" thread={thread_id_string}{exception_string}")


# class Crashdump(_ProcessedCommand):
#     """???."""
#
#     class Response(_ProcessedResponse):
#         pass
#
#     def __init__(self, handler=None):
#         super().__init__("crashdump", response_class=self.Response, handler=handler)


class DbgnameGet(_ProcessedCommand):
    """Gets the XBOX devkit name."""

    class Response(_ProcessedResponse):
        def __init__(self, response: rdcp_response.RDCPResponse):
            super().__init__(response)

            if not self.ok:
                self.name = None
                return

            self.name = response.data.decode("utf-8")
            if self.name.startswith('"'):
                self.name = self.name[1:-1]

        @property
        def _body_str(self) -> str:
            return f" {self.name}"

    def __init__(self, handler=None):
        super().__init__("dbgname", response_class=self.Response, handler=handler)


class DbgnameSet(_ProcessedCommand):
    """Sets the XBOX devkit name."""

    class Response(_ProcessedResponse):
        pass

    def __init__(self, new_name, handler=None):
        super().__init__("dbgname", response_class=self.Response, handler=handler)
        if new_name:
            self.body = bytes(f' name="{new_name}"', "utf-8")


class DbgOptions(_ProcessedCommand):
    """Sets or gets the "crashdump" and "dpctrace" flags."""

    class Response(_ProcessedResponse):
        def __init__(self, response: rdcp_response.RDCPResponse):
            super().__init__(response)

            if not self.ok:
                self.enable_crashdump = None
                self.enable_dpctrace = None
                return

            entries = response.parse_data_map()
            self.enable_crashdump = rdcp_response.get_bool_property(
                entries, b"crashdump"
            )
            self.enable_dpctrace = rdcp_response.get_bool_property(entries, b"dpctrace")

        @property
        def _body_str(self) -> str:
            return f" enable_crashdump={self.enable_crashdump} enable_dpctrace={self.enable_dpctrace}"

    def __init__(self, enable_crashdump=None, enable_dpctrace=None, handler=None):
        super().__init__("dbgoptions", response_class=self.Response, handler=handler)

        setters = []

        def value(flag):
            if flag:
                return "0x01"
            return "0x00"

        if enable_crashdump is not None:
            setters.append(f"crashdump={value(enable_crashdump)}")
        if enable_dpctrace is not None:
            setters.append(f"dpctrace={value(enable_dpctrace)}")
        if setters:
            setter_str = " ".join(setters)
            self._body = bytes(f" {setter_str}", "utf-8")


class Debugger(_ProcessedCommand):
    """Connects or disconnects the debugger."""

    class Response(_ProcessedResponse):
        pass

    def __init__(self, connect=True, handler=None):
        super().__init__("debugger", response_class=self.Response, handler=handler)
        cmd = "connect" if connect else "disconnect"
        self.body = bytes(f" {cmd}", "utf-8")


class DebugMode(_ProcessedCommand):
    """?Enables debugmode flags?."""

    class Response(_ProcessedResponse):
        pass

    def __init__(self, connect=True, handler=None):
        super().__init__("debugmode", response_class=self.Response, handler=handler)


class DirList(_ProcessedCommand):
    """Lists contents of a path."""

    class Response(_ProcessedResponse):
        pass

    def __init__(self, name, handler=None):
        super().__init__("dirlist", response_class=self.Response, handler=handler)
        self.body = bytes(f' name="name"', "utf-8")


class DMVersion(_ProcessedCommand):
    """Returns the debug monitor version."""

    class Response(_ProcessedResponse):
        def __init__(self, response: rdcp_response.RDCPResponse):
            super().__init__(response)

            if not self.ok:
                self.version = None
                return

            self.version = response.data.decode("utf-8")

        @property
        def _body_str(self) -> str:
            return f" version={self.version}"

    def __init__(self, handler=None):
        super().__init__("dmversion", response_class=self.Response, handler=handler)


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
