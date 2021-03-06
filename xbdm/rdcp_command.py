"""Provides utilities in support of Remote Debugging and Control Protocol."""
import binascii
import enum
import ipaddress
import logging
import signal
from typing import Callable
from typing import Dict
from typing import Mapping
from typing import Optional

from . import rdcp_response

logger = logging.getLogger(__name__)


class ProcessedResponseCatcher:
    """Captures a ProcessedResponse derived object and proxies it."""

    def __init__(self):
        self.response: Optional[_ProcessedResponse] = None

    def __call__(self, *args, **kwargs):
        self.response = args[0]

    def __getattr__(self, item):
        if not self.response:
            raise SystemError()
        return getattr(self.response, item)

    @property
    def has_response(self) -> bool:
        return self.response is not None


# COMMANDS = {
#     "adminpw",
#     "altaddr",  #  > addr=0x0a000210
#     "authuser",  # (resp=QWORD name=STRING) > 414:access denied  # Looks like "passwd" is another param maybe for an older XDK?
#     # "boxid",  # Can only be executed if security is enabled.
#     "capctrl",  # "start" or none - starts or stops profiling capture
#     "crashdump",
#     "d3dopcode",
#     "debugger",
#     "debugmode",
#     "dedicate",
#     "deftitle",
#     "delete",
#     "dirlist",
#     "dmversion",
#     "drivefreespace",
#     "drivelist",
#     "dvdblk",
#     "dvdperf",
#     "fileeof",
#     "flash",
#     "fmtfat",
#     "funccall",
#     "getcontext",
#     "getd3dstate",
#     "getextcontext",
#     "getfile",
#     "getfileattributes",
#     "getgamma",
#     "getmem",
#     "getmem2",
#     "getpalette",
#     "getpid",
#     "getsum",
#     "getsurf",
#     "getuserpriv",
#     "getutildrvinfo",
#     "go",
#     "gpucount",
#     "halt",
#     "irtsweep",
#     "isbreak",
#     "isdebugger",
#     "isstopped",
#     "kd",
#     "keyxchg",
#     "lockmode",
#     "lop",
#     "magicboot",
#     "memtrack",
#     "mkdir",
#     "mmglobal",
#     "modlong",
#     "modsections",
#     "modules",
#     "nostopon",
#     "notify",
#     "notifyat",
#     "pbsnap",
#     "pclist",
#     "pdbinfo",
#     "pssnap",
#     "querypc",
#     "reboot",
#     "rename",
#     "resume",
#     "screenshot",
#     "sendfile",
#     "servname",
#     "setconfig",
#     "setcontext",
#     "setfileattributes",
#     "setsystime",
#     "setuserpriv",
#     "signcontent",
#     "stop",
#     "stopon",
#     "suspend",
#     "sysfileupd",
#     "systime",  # high=0x1d7c3df low=0xb7852a80
#     "threadinfo",
#     "threads",
#     "title",
#     "user",
#     "userlist",
#     "vssnap",
#     "walkmem",
#     "writefile",
#     "xbeinfo",
#     "xtlinfo",
# }


class RDCPCommand:
    """Models a Remote Debugging and Control Protocol command."""

    TERMINATOR = b"\r\n"
    STR_BODY_CUTOFF = 128

    def __init__(
        self,
        command: str,
        body: bytes = None,
        response_handler: Callable[[rdcp_response.RDCPResponse], bool] = None,
    ):
        self.command = command.lower()
        self.body = body
        self._response_handler = response_handler
        self._binary_response_length = 0
        self._binary_payload = None
        self._dedicate_notification_mode = False

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

    @property
    def expected_binary_response_length(self) -> int:
        if self._binary_response_length:
            return self._binary_response_length
        return 0

    @property
    def dedicate_notification_mode(self) -> bool:
        return self._dedicate_notification_mode

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
            return False
        return self._response_handler(response)


class RDCPBinaryPayload(RDCPCommand):
    """Models a raw set of bytes."""

    def __init__(self, original_command: RDCPCommand):
        """Creates a new RDCPBinaryPayload instance from the given command, stealing its response_handler."""
        super().__init__(
            original_command.command + "-payload",
            response_handler=original_command._response_handler,
        )
        original_command._response_handler = None
        self.payload = original_command._binary_payload
        assert self.payload

    def __str__(self):
        ret = f"{self.__class__.__name__}[{len(self.payload)}])"

    def serialize(self) -> bytes:
        return self.payload


class ProcessedCommand(RDCPCommand):
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
        self.status = response.status
        self.message = response.message
        self.raw_body = response.data

    @property
    def ok(self):
        return self.status == rdcp_response.RDCPResponse.STATUS_OK

    @property
    def _body_str(self) -> str:
        return ""

    @property
    def pretty_message(self) -> Optional[str]:
        if self.ok:
            return None

        if self.message:
            try:
                message = self.message.decode("utf-8")
            except UnicodeDecodeError:
                message = "<Non unicode data>"
        else:
            message = rdcp_response.RDCPResponse.STATUS_CODES.get(
                self.status, "??INVALID??"
            )
        return f"{self.status}: {message}"

    def __str__(self):
        body = self._body_str
        if body:
            body = f" {body}"

        ret = f"{self.__class__.__qualname__}::{self.pretty_message} {body}"
        return ret


class _ProcessedRawBodyResponse(_ProcessedResponse):
    def __init__(self, response: rdcp_response.RDCPResponse):
        super().__init__(response)
        self._body = response.data

    @property
    def _body_str(self) -> str:
        return self._body.decode("utf-8")


class AltAddr(ProcessedCommand):
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
            return self.alt_ip

    def __init__(self, handler=None):
        super().__init__("altaddr", response_class=self.Response, handler=handler)


class _Break(ProcessedCommand):
    """Manages breakpoints."""

    class Response(_ProcessedRawBodyResponse):
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
        self.body = bytes(f" {clear_string}addr={address}", "utf-8")


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
        size_string = f" size={size}" if not clear else ""
        self.body = bytes(
            f" {clear_string}{access_type}=0x%08X{size_string}" % address, "utf-8"
        )


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


class Bye(ProcessedCommand):
    """Closes the connection gracefully."""

    class Response(_ProcessedResponse):
        pass

    def __init__(self, handler=None):
        super().__init__("bye", response_class=self.Response, handler=handler)


class ProfilerCaptureControl(ProcessedCommand):
    """Starts or stops profiling capture."""

    class Response(_ProcessedRawBodyResponse):
        pass

    def __init__(self, start: bool = True, handler=None):
        super().__init__("capctrl", response_class=self.Response, handler=handler)
        if start:
            self.body = b" start"


class Continue(ProcessedCommand):
    """Continues execution of the given thread."""

    class Response(_ProcessedResponse):
        pass

    def __init__(self, thread_id: int, exception: bool = False, handler=None):
        # TODO: Document 'exception' flag behavior.
        super().__init__("continue", response_class=self.Response, handler=handler)
        exception_string = " exception" if exception else ""
        self.body = bytes(f" thread={thread_id}{exception_string}", "utf-8")


# class Crashdump(_ProcessedCommand):
#     """???."""
#
#     class Response(_ProcessedResponse):
#         pass
#
#     def __init__(self, handler=None):
#         super().__init__("crashdump", response_class=self.Response, handler=handler)


class DbgnameGet(ProcessedCommand):
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
            return {self.name}

    def __init__(self, handler=None):
        super().__init__("dbgname", response_class=self.Response, handler=handler)


class DbgnameSet(ProcessedCommand):
    """Sets the XBOX devkit name."""

    class Response(_ProcessedResponse):
        pass

    def __init__(self, new_name, handler=None):
        super().__init__("dbgname", response_class=self.Response, handler=handler)
        if new_name:
            self.body = bytes(f' name="{new_name}"', "utf-8")


class DbgOptions(ProcessedCommand):
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
            return f"enable_crashdump={self.enable_crashdump} enable_dpctrace={self.enable_dpctrace}"

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


class Debugger(ProcessedCommand):
    """Connects or disconnects the debugger."""

    class Response(_ProcessedResponse):
        pass

    def __init__(self, connect=True, handler=None):
        super().__init__("debugger", response_class=self.Response, handler=handler)
        cmd = "connect" if connect else "disconnect"
        self.body = bytes(f" {cmd}", "utf-8")


class DebugMode(ProcessedCommand):
    """?Enables debugmode flags?."""

    class Response(_ProcessedResponse):
        pass

    def __init__(self, handler=None):
        super().__init__("debugmode", response_class=self.Response, handler=handler)


class Dedicate(ProcessedCommand):
    """Sets connection as dedicated."""

    class Response(_ProcessedRawBodyResponse):
        pass

    def __init__(self, global_enable=None, handler_name=None, handler=None):
        super().__init__("dedicate", response_class=self.Response, handler=handler)
        if global_enable:
            self.body = b" global"
        elif handler_name:
            self.body = bytes(f' handler="{handler_name}"', "utf-8")


class DefTitle(ProcessedCommand):
    """???"""

    class Response(_ProcessedRawBodyResponse):
        pass

    def __init__(
        self,
        launcher: bool = False,
        name: Optional[str] = None,
        directory: Optional[str] = None,
        handler=None,
    ):
        super().__init__("deftitle", response_class=self.Response, handler=handler)

        if not name:
            self.body = b" none"
            return

        if launcher:
            self.body = b" launcher"
            return

        if not name:
            raise ValueError("Missing required 'name' parameter.")

        if not directory:
            raise ValueError("Missing required 'directory' parameter.")

        body = f' name="{name}" dir="{directory}"'
        self.body = bytes(body, "utf-8")


class Delete(ProcessedCommand):
    """Deletes a file."""

    class Response(_ProcessedRawBodyResponse):
        pass

    def __init__(self, path, is_directory=False, handler=None):
        super().__init__("delete", response_class=self.Response, handler=handler)
        if is_directory:
            dir_flag = " dir"
        else:
            dir_flag = ""

        self.body = bytes(f' name="{path}"{dir_flag}', "utf-8")


class DirList(ProcessedCommand):
    """Lists contents of a path."""

    class Response(_ProcessedResponse):
        def __init__(self, response: rdcp_response.RDCPResponse):
            super().__init__(response)

            self.entries = []

            if not self.ok:
                return

            entries = response.parse_data_map_array()
            for entry in entries:
                entry_info = {
                    "name": rdcp_response.get_utf_property(entry, b"name"),
                    "filesize": rdcp_response.get_qword_property(
                        entry, b"sizelo", b"sizehi"
                    ),
                    "create_timestamp": rdcp_response.get_qword_property(
                        entry, b"createlo", b"createhi"
                    ),
                    "change_timestamp": rdcp_response.get_qword_property(
                        entry, b"changelo", b"changehi"
                    ),
                    "directory": rdcp_response.get_bool_property(entry, b"directory"),
                }

                self.entries.append(entry_info)

        @property
        def ok(self):
            return self.status == rdcp_response.RDCPResponse.STATUS_MULTILINE_RESPONSE

        @property
        def _body_str(self) -> str:
            return f"{self.entries}"

    def __init__(self, name, handler=None):
        super().__init__("dirlist", response_class=self.Response, handler=handler)
        self.body = bytes(f' name="{name}"', "utf-8")


class DMVersion(ProcessedCommand):
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
            return f"version={self.version}"

    def __init__(self, handler=None):
        super().__init__("dmversion", response_class=self.Response, handler=handler)


class DriveFreeSpace(ProcessedCommand):
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
            self.free_to_caller = rdcp_response.get_qword_property(
                entries, b"freetocallerlo", b"freetocallerhi"
            )

            self.total_bytes = rdcp_response.get_qword_property(
                entries, b"totalbyteslo", b"totalbyteshi"
            )

            self.total_free_bytes = rdcp_response.get_qword_property(
                entries, b"totalfreebyteslo", b"totalfreebyteshi"
            )

        @property
        def ok(self):
            return self.status == rdcp_response.RDCPResponse.STATUS_MULTILINE_RESPONSE

        @property
        def _body_str(self) -> str:
            return f"total: {self.total_bytes} total free: {self.total_free_bytes} free to caller: {self.free_to_caller}"

    def __init__(self, drive_letter, handler=None):
        super().__init__(
            "drivefreespace", response_class=self.Response, handler=handler
        )
        self.body = bytes(f' name="{drive_letter}:\\"', "utf-8")


class DriveList(ProcessedCommand):
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
            return f"{self.drives}"

    def __init__(self, handler=None):
        super().__init__("drivelist", response_class=self.Response, handler=handler)


class FuncCall(ProcessedCommand):
    """??? thread must be stopped, just returns OK"""

    class Response(_ProcessedRawBodyResponse):
        pass

    def __init__(self, thread_id: int, handler=None):
        super().__init__("funccall", response_class=self.Response, handler=handler)
        self.body = bytes(f" thread={thread_id}", "utf-8")


class GetContext(ProcessedCommand):
    """Gets the register context for the given thread."""

    class Response(_ProcessedResponse):
        def __init__(self, response: rdcp_response.RDCPResponse):
            super().__init__(response)

            self.registers: Dict[str, Optional[int]] = {
                "Ebp": None,
                "Esp": None,
                "Eip": None,
                "EFlags": None,
                "Eax": None,
                "Ebx": None,
                "Ecx": None,
                "Edx": None,
                "Edi": None,
                "Esi": None,
                "Cr0NpxState": None,
            }

            if not self.ok:
                return

            entries = response.parse_data_map()
            for key, value in entries.items():
                key = key.decode("utf-8")
                if key not in self.registers:
                    logger.error(f"UNKNOWN REGISTER {key}")

                self.registers[key] = int(value.decode("utf-8"), 0)

        @property
        def ok(self):
            return self.status == rdcp_response.RDCPResponse.STATUS_MULTILINE_RESPONSE

        @property
        def _body_str(self) -> str:
            registers = [
                f"{key} {'0x%X' % value if value is not None else '???'}"
                for key, value in self.registers.items()
            ]
            return ", ".join(registers)

    def __init__(
        self,
        thread_id: int,
        enable_control: bool = False,
        enable_integer: bool = False,
        enable_float: bool = False,
        handler=None,
    ):
        super().__init__("getcontext", response_class=self.Response, handler=handler)
        flags = []
        # There appears to be a bug where 'full' doesn't return Cr0NpxState.
        # if enable_control and enable_integer and enable_float:
        #     flags.append("full")
        # else:
        if enable_control:
            flags.append("control")
        if enable_integer:
            flags.append("int")
        if enable_float:
            flags.append("fp")
        if not flags:
            flags = ""
        else:
            flags = " " + " ".join(flags)
        self.body = bytes(f" thread={thread_id}{flags}", "utf-8")


class GetD3DState(ProcessedCommand):
    """Retrieves the current D3D state."""

    class Response(_ProcessedResponse):
        def __init__(self, response: rdcp_response.RDCPResponse):
            super().__init__(response)

            self.printable_data = ""
            self.data = bytes()

            if not self.ok:
                return

            self.data = response.data
            # TODO: Parse the response data and drop this.
            self.printable_data = binascii.hexlify(self.data)

        @property
        def ok(self):
            return self.status == rdcp_response.RDCPResponse.STATUS_BINARY_RESPONSE

        @property
        def _body_str(self) -> str:
            return f"{self.printable_data}"

    def __init__(
        self,
        handler=None,
    ):
        super().__init__("getd3dstate", response_class=self.Response, handler=handler)
        self._binary_response_length = 1180


class GetExtContext(ProcessedCommand):
    """Gets thread context information as a struct."""

    class Response(_ProcessedResponse):
        def __init__(self, response: rdcp_response.RDCPResponse):
            super().__init__(response)

            self.printable_data = ""
            self.data = bytes()

            if not self.ok:
                return

            self.data = response.data
            # TODO: Parse the response data and drop this.
            self.printable_data = binascii.hexlify(self.data)

        @property
        def ok(self):
            return self.status == rdcp_response.RDCPResponse.STATUS_BINARY_RESPONSE

        @property
        def _body_str(self) -> str:
            return f"{self.printable_data}"

    def __init__(self, thread_id: int, handler=None):
        super().__init__("getextcontext", response_class=self.Response, handler=handler)
        self.body = bytes(f" thread={thread_id}", "utf-8")
        self._binary_response_length = (
            rdcp_response.RDCPResponse.BINARY_FIRST_DWORD_HAS_SIZE
        )


class GetFile(ProcessedCommand):
    """Retrieves the content of a file."""

    class Response(_ProcessedRawBodyResponse):
        def __init__(self, response: rdcp_response.RDCPResponse):
            super().__init__(response)

            self.printable_data = ""
            self.data = bytes()

            if not self.ok:
                return

            self.data = response.data
            # TODO: Consider dropping printable_data.
            self.printable_data = binascii.hexlify(self.data)

        @property
        def ok(self):
            return self.status == rdcp_response.RDCPResponse.STATUS_BINARY_RESPONSE

        @property
        def _body_str(self) -> str:
            return f"{self.printable_data}"

    def __init__(self, name: str, offset_and_size: (int, int) = None, handler=None):
        super().__init__("getfile", response_class=self.Response, handler=handler)
        if offset_and_size:
            chunk_str = " offset=0x%X size=0x%X" % offset_and_size
        else:
            chunk_str = ""

        self.body = bytes(f' name="{name}"{chunk_str}', "utf-8")
        self._binary_response_length = (
            rdcp_response.RDCPResponse.BINARY_FIRST_DWORD_HAS_SIZE
        )


class GetFileAttributes(ProcessedCommand):
    """Retrieves attributes of a file."""

    class Response(_ProcessedResponse):
        def __init__(self, response: rdcp_response.RDCPResponse):
            super().__init__(response)

            self.filesize = None
            self.create_timestamp = None
            self.change_timestamp = None
            self.flags = {}

            if not self.ok:
                return

            entries = response.parse_data_map()
            handled_keys = {
                b"sizelo",
                b"sizehi",
                b"createlo",
                b"createhi",
                b"changelo",
                b"changehi",
                b"directory",
            }
            self.filesize = rdcp_response.get_qword_property(
                entries, b"sizelo", b"sizehi"
            )
            self.create_timestamp = rdcp_response.get_qword_property(
                entries, b"createlo", b"createhi"
            )
            self.change_timestamp = rdcp_response.get_qword_property(
                entries, b"changelo", b"changehi"
            )
            self.directory = rdcp_response.get_bool_property(entries, b"directory")

            for key in entries.keys():
                if key in handled_keys:
                    continue
                self.flags[key.decode("utf-8")] = rdcp_response.get_bool_property(
                    entries, key
                )

        @property
        def ok(self):
            return self.status == rdcp_response.RDCPResponse.STATUS_MULTILINE_RESPONSE

        @property
        def _body_str(self) -> str:
            return f" size: {self.filesize} create_time: {self.create_timestamp} change_time: {self.change_timestamp} directory: {self.directory} flags: {self.flags}"

    def __init__(self, name: str, handler=None):
        super().__init__(
            "getfileattributes", response_class=self.Response, handler=handler
        )
        self.body = bytes(f' name="{name}"', "utf-8")


class GetGamma(ProcessedCommand):
    """Retrieves gamma information."""

    class Response(_ProcessedResponse):
        def __init__(self, response: rdcp_response.RDCPResponse):
            super().__init__(response)

            self.printable_data = ""
            self.data = bytes()

            if not self.ok:
                return

            self.data = response.data
            # TODO: Consider dropping printable_data.
            self.printable_data = binascii.hexlify(self.data)

        @property
        def ok(self):
            return self.status == rdcp_response.RDCPResponse.STATUS_BINARY_RESPONSE

        @property
        def _body_str(self) -> str:
            return f"{self.printable_data}"

    def __init__(self, handler=None):
        super().__init__("getgamma", response_class=self.Response, handler=handler)
        self._binary_response_length = 768


class GetMem(ProcessedCommand):
    """Gets the contents of a block of memory."""

    class Response(_ProcessedResponse):
        def __init__(self, response: rdcp_response.RDCPResponse):
            super().__init__(response)

            self.printable_data = ""
            self.data = bytes()

            if not self.ok:
                return

            self.printable_data, self.data = response.parse_hex_data()

        @property
        def ok(self):
            return self.status == rdcp_response.RDCPResponse.STATUS_MULTILINE_RESPONSE

        @property
        def _body_str(self) -> str:
            return f"{self.printable_data}"

    def __init__(self, addr, length, handler=None):
        super().__init__("getmem", response_class=self.Response, handler=handler)
        addr = "0x%X" % addr
        length = "0x%X" % length
        self.body = bytes(f" addr={addr} length={length}", "utf-8")


class GetMemBinary(ProcessedCommand):
    """Gets the contents of a block of memory as a binary chunk."""

    class Response(_ProcessedResponse):
        def __init__(self, response: rdcp_response.RDCPResponse):
            super().__init__(response)

            self.data = bytes()

            if not self.ok:
                return

            self.data = response.data

        @property
        def ok(self):
            return self.status == rdcp_response.RDCPResponse.STATUS_BINARY_RESPONSE

        @property
        def _body_str(self) -> str:
            return f"{self.data.hex()}"

    def __init__(self, addr, length, handler=None):
        super().__init__("getmem2", response_class=self.Response, handler=handler)
        self._binary_response_length = length
        addr = "0x%X" % addr
        length = "0x%X" % length
        self.body = bytes(f" ADDR={addr} LENGTH={length}", "utf-8")


class GetPalette(ProcessedCommand):
    """Retrieves palette information (D3DINT_GET_PALETTE)."""

    class Response(_ProcessedRawBodyResponse):
        # TODO: Implement. Calling on the dashboard gives an error.
        pass

    def __init__(self, stage: int, handler=None):
        super().__init__("getpalette", response_class=self.Response, handler=handler)
        self.body = bytes(" STAGE=0x%X" % stage, "utf-8")


class GetProcessID(ProcessedCommand):
    """Retrieves the ID of the currently running process (must be debuggable)."""

    class Response(_ProcessedResponse):
        def __init__(self, response: rdcp_response.RDCPResponse):
            super().__init__(response)

            self.process_id = None

            if not self.ok:
                return

            entries = response.parse_data_map()
            self.process_id = rdcp_response.get_int_property(entries, b"pid")

        @property
        def _body_str(self) -> str:
            return f"process_id: {self.process_id}"

    def __init__(self, handler=None):
        super().__init__("getpid", response_class=self.Response, handler=handler)


class GetChecksum(ProcessedCommand):
    """Returns the checksum for a memory region."""

    class Response(_ProcessedResponse):
        def __init__(self, response: rdcp_response.RDCPResponse):
            super().__init__(response)

            self.data = bytes()

            if not self.ok:
                return

            self.data = response.data

        @property
        def ok(self):
            return self.status == rdcp_response.RDCPResponse.STATUS_BINARY_RESPONSE

        @property
        def _body_str(self) -> str:
            return f"{self.data.hex()}"

    def __init__(self, addr: int, length: int, blocksize: int, handler=None):
        super().__init__("getsum", response_class=self.Response, handler=handler)
        # BLOCKSIZE < 8 will hang the device.
        assert blocksize >= 8
        self.body = bytes(
            " ADDR=0x%X LENGTH=0x%X BLOCKSIZE=0x%X" % (addr, length, blocksize), "utf-8"
        )
        self._binary_response_length = 384 // blocksize


class GetSurface(ProcessedCommand):
    """???"""

    class Response(_ProcessedRawBodyResponse):
        pass

    def __init__(self, surface_id: int, handler=None):
        super().__init__("getsurf", response_class=self.Response, handler=handler)
        self.body = bytes(f" id=0x%X" % surface_id, "utf-8")


class GetUserPrivileges(ProcessedCommand):
    """Gets the privilege flags for a user."""

    class Response(_ProcessedResponse):
        def __init__(self, response: rdcp_response.RDCPResponse):
            super().__init__(response)

            self.flags = {}

            if not self.ok:
                return

            entries = response.parse_data_map()
            self.flags = {
                key.decode("utf-8"): rdcp_response.get_bool_property(entries, key)
                for key in entries.keys()
            }

        @property
        def _body_str(self) -> str:
            return f"flags: {self.flags}"

    def __init__(self, username: Optional[str] = None, handler=None):
        super().__init__("getuserpriv", response_class=self.Response, handler=handler)
        if not username:
            self.body = bytes(" me", "utf-8")
        else:
            self.body = bytes(f' name="{username}"', "utf-8")


class GetUtilityDriveInfo(ProcessedCommand):
    """Gets information about the mounted utility partitions."""

    class Response(_ProcessedResponse):
        def __init__(self, response: rdcp_response.RDCPResponse):
            super().__init__(response)

            self.partitions = {}

            if not self.ok:
                return

            entries = response.parse_data_map()
            self.partitions = {
                key.decode("utf-8"): rdcp_response.get_int_property(entries, key)
                for key in entries.keys()
            }

        @property
        def _body_str(self) -> str:
            return f"partitions: {self.partitions}"

    def __init__(self, handler=None):
        super().__init__(
            "getutildrvinfo", response_class=self.Response, handler=handler
        )


class Go(ProcessedCommand):
    """Resumes execution of all threads."""

    class Response(_ProcessedRawBodyResponse):
        pass

    def __init__(self, handler=None):
        super().__init__("go", response_class=self.Response, handler=handler)


class GPUCounter(ProcessedCommand):
    """Enables or disables GPU performance counters."""

    class Response(_ProcessedResponse):
        pass

    def __init__(self, enable: bool = True, handler=None):
        super().__init__("gpucount", response_class=self.Response, handler=handler)
        self.body = b" enable" if enable else b" disable"


class Halt(ProcessedCommand):
    """Halts execution of the given thread or all threads."""

    class Response(_ProcessedRawBodyResponse):
        pass

    def __init__(self, thread_id: Optional[int] = None, handler=None):
        super().__init__("halt", response_class=self.Response, handler=handler)
        if thread_id is not None:
            self.body = bytes(f" thread={thread_id}", "utf-8")


class IsBreak(ProcessedCommand):
    """Checks to see if a breakpoint is set at the given address."""

    class Response(_ProcessedResponse):
        TYPE_NONE = 0
        TYPE_WRITE = 1
        TYPE_READ_OR_WRITE = 2
        TYPE_EXECUTE = 3
        TYPE_ADDRESS = 4

        def __init__(self, response: rdcp_response.RDCPResponse):
            super().__init__(response)

            self.type = None

            if not self.ok:
                return

            entries = response.parse_data_map()
            self.type = rdcp_response.get_int_property(entries, b"type")

        @property
        def _body_str(self) -> str:
            type_str = "???"
            if self.type == self.TYPE_NONE:
                "No breakpoint"
            elif self.type == self.TYPE_WRITE:
                "Write"
            elif self.type == self.TYPE_READ_OR_WRITE:
                "Read/Write"
            elif self.type == self.TYPE_EXECUTE:
                "Execute"
            elif self.type == self.TYPE_ADDRESS:
                "Previously set breakpoint at address"

            return f"type: {type_str}({self.type})"

    def __init__(self, addr, handler=None):
        super().__init__("isbreak", response_class=self.Response, handler=handler)
        addr_str = "0x%X" % addr
        self.body = bytes(f" addr={addr_str}", "utf-8")


class IsDebugger(ProcessedCommand):
    """Checks to see if the debugger is allowed to attach?"""

    class Response(_ProcessedResponse):
        def __init__(self, response: rdcp_response.RDCPResponse):
            super().__init__(response)

            self.debugger_attached: Optional[bool] = None

            if not self.ok:
                return

            self.debugger_attached = (
                self.status == rdcp_response.RDCPResponse.STATUS_ERR_EXISTS
            )

        @property
        def ok(self) -> bool:
            return (
                self.status == rdcp_response.RDCPResponse.STATUS_OK
                or self.status == rdcp_response.RDCPResponse.STATUS_ERR_EXISTS
            )

        @property
        def _body_str(self) -> str:
            if self.debugger_attached:
                return "Debugger attached"
            return "No debugger attached"

    def __init__(self, handler=None):
        super().__init__("isdebugger", response_class=self.Response, handler=handler)


class IsStopped(ProcessedCommand):
    """Checks to see if the given thread is stopped."""

    class StopReason:
        def __init__(
            self, reason: str, signal: int, info_items: Optional[Dict[str, str]] = None
        ):
            self.reason = reason
            self.signal = signal
            self.info_items = info_items

        def __str__(self):
            ret = f"{self.__class__.__name__}: {self.reason}"
            if self.info_items:
                ret += "> "
                for key, value in self.info_items.items():
                    ret += f" {key}: {value}"
            return ret

    class Unknown(StopReason):
        def __init__(self):
            super().__init__("unknown reason", signal.SIGTRAP)

    class Debugstr(StopReason):
        def __init__(self, entries: Dict[bytes, bytes]):
            self.thread_id = rdcp_response.get_int_property(entries, b"thread")
            super().__init__(
                "debugstr", signal.SIGTRAP, {"thread": "%d" % self.thread_id}
            )

    class Assertion(StopReason):
        def __init__(self, entries: Dict[bytes, bytes]):
            self.thread_id = rdcp_response.get_int_property(entries, b"thread")
            super().__init__(
                "assert prompt", signal.SIGTRAP, {"thread": "%d" % self.thread_id}
            )

    class Breakpoint(StopReason):
        def __init__(self, entries: Dict[bytes, bytes]):
            self.thread_id: int = rdcp_response.get_int_property(entries, b"thread")
            self.address: int = rdcp_response.get_int_property(entries, b"addr")
            super().__init__(
                "breakpoint",
                signal.SIGTRAP,
                {
                    "thread": "%d" % self.thread_id,
                    "address": "0x%08X" % self.address,
                },
            )

    class SingleStep(StopReason):
        def __init__(self, entries: Dict[bytes, bytes]):
            self.thread_id: int = rdcp_response.get_int_property(entries, b"thread")
            self.address: int = rdcp_response.get_int_property(entries, b"addr")
            super().__init__(
                "single step",
                signal.SIGTRAP,
                {
                    "thread": "%d" % self.thread_id,
                    "address": "0x%08X" % self.address,
                },
            )

    class DataBreakpoint(StopReason):
        ACCESS_INVALID = -1
        ACCESS_READ = 0
        ACCESS_WRITE = 1
        ACCESS_EXECUTE = 2

        def __init__(self, entries: Dict[bytes, bytes]):
            self.thread_id: int = rdcp_response.get_int_property(entries, b"thread")
            self.address: int = rdcp_response.get_int_property(entries, b"addr")
            self.break_type: int = self.ACCESS_INVALID
            self.access_address: int = 0

            reason_name = ""
            for index, key in enumerate([b"read", b"write", b"execute"]):
                addr = rdcp_response.get_int_property(entries, key, -1)
                if addr == -1:
                    continue

                self.break_type = index
                reason_name = key.decode("utf-8")
                self.access_address = addr
                break

            super().__init__(
                "data breakpoint",
                signal.SIGTRAP,
                {
                    "thread": "%d" % self.thread_id,
                    "address": "0x%08X" % self.address,
                    "access": "%s@0x%08X" % (reason_name, self.access_address),
                },
            )

    class ExecutionStateChange(StopReason):
        STATE_INVALID = -1
        STATE_STOPPED = 0
        STATE_STARTED = 1
        STATE_REBOOTING = 2
        STATE_PENDING = 3

        def __init__(self, info: str):
            self.state_string = info
            states = ["stopped", "started", "rebooting", "pending"]
            self.state = states.index(info)
            super().__init__(
                "execution state changed",
                signal.SIGTRAP,
                {"new_state": self.state_string},
            )

    class Exception(StopReason):
        FLAG_NONE = 0
        FLAG_FIRST_CHANCE = 1
        FLAG_NON_CONTINUABLE = 2
        FLAG_ACCESS_VIOLATION_READ = 3
        FLAG_ACCESS_VIOLATION_WRITE = 4

        def __init__(self, entries: Dict[bytes, bytes]):

            self.code: int = rdcp_response.get_int_property(entries, b"code")
            self.thread: int = rdcp_response.get_int_property(entries, b"thread")
            self.address: int = rdcp_response.get_int_property(entries, b"address")

            attributes: Dict[str, str] = {
                "code": "0x%08X" % self.code,
                "thread": "%d" % self.thread,
                "address": "0x%08X" % self.address,
            }

            self.is_first_chance_exception: bool = rdcp_response.get_bool_property(
                entries, b"first"
            )
            if self.is_first_chance_exception:
                attributes["first_chance_exception"] = "true"

            self.is_non_continuable: bool = rdcp_response.get_bool_property(
                entries, b"noncont"
            )
            if self.is_non_continuable:
                attributes["non_continuable"] = "true"

            self.access_violation_address: Optional[int] = None
            self.is_access_violation_read: bool = False
            self.is_access_violation_write: bool = False

            access_violation_addr = rdcp_response.get_int_property(entries, b"read", -1)
            if access_violation_addr != -1:
                self.is_access_violation_read: bool = True
                self.access_violation_address = access_violation_addr
                attributes["access_violation_type"] = "read"
                attributes["access_violation_address"] = (
                    "0x%08X" % self.access_violation_address
                )

            else:
                access_violation_addr = rdcp_response.get_int_property(
                    entries, b"write", -1
                )
                if access_violation_addr != -1:
                    self.is_access_violation_write: bool = True
                    self.access_violation_address = access_violation_addr
                    attributes["access_violation_type"] = "write"
                    attributes["access_violation_address"] = (
                        "0x%08X" % self.access_violation_address
                    )

            self.num_param: Optional[int] = None
            self.params: Optional[int] = None
            if not (self.is_access_violation_read or self.is_access_violation_write):
                self.num_param = rdcp_response.get_int_property(entries, b"nparams")
                self.params = rdcp_response.get_int_property(entries, b"params")
                attributes["nparam"] = "%d" % self.num_param
                attributes["params"] = "0x%08X" % self.params

            super().__init__("exception", signal.SIGTRAP, attributes)

    class CreateThread(StopReason):
        def __init__(self, entries: Dict[bytes, bytes]):
            self.thread_id: int = rdcp_response.get_int_property(entries, b"thread")
            self.start: int = rdcp_response.get_int_property(entries, b"start")
            super().__init__(
                "create thread",
                signal.SIGTRAP,
                {
                    "thread": "%d" % self.thread_id,
                    "start_address": "0x%08X" % self.start,
                },
            )

    class TerminateThread(StopReason):
        def __init__(self, entries: Dict[bytes, bytes]):
            self.thread_id: int = rdcp_response.get_int_property(entries, b"thread")
            super().__init__(
                "terminate thread", signal.SIGTRAP, {"thread": "%d" % self.thread_id}
            )

    class ModuleLoad(StopReason):
        def __init__(self, entries: Dict[bytes, bytes]):
            self.name: str = rdcp_response.get_utf_property(entries, b"name")
            self.base_address: int = rdcp_response.get_int_property(entries, b"base")
            self.size: int = rdcp_response.get_int_property(entries, b"size")
            self.checksum: int = rdcp_response.get_int_property(entries, b"check")
            self.timestamp: int = rdcp_response.get_int_property(entries, b"timestamp")
            self.tls: bool = rdcp_response.get_bool_property(entries, b"tls")
            self.xbe: bool = rdcp_response.get_bool_property(entries, b"xbe")

            attributes = {
                "name": self.name,
                "size": "%d" % self.size,
                "base_address": "0x%08x" % self.base_address,
                "checksum": "0x%08x" % self.checksum,
                "timestamp": "0x%08x" % self.timestamp,
            }
            if self.tls:
                attributes["has_thread_local_storage"] = "true"
            if self.xbe:
                attributes["is_xbe"] = "true"

            super().__init__("module load", signal.SIGTRAP, attributes)

    class _SectionAction(StopReason):
        def __init__(self, action: str, entries: Dict[bytes, bytes]):
            self.name: str = rdcp_response.get_utf_property(entries, b"name")
            self.base_address: int = rdcp_response.get_int_property(entries, b"base")
            self.size: int = rdcp_response.get_int_property(entries, b"size")
            self.index: int = rdcp_response.get_int_property(entries, b"index")
            self.flags: int = rdcp_response.get_int_property(entries, b"flags")

            attributes = {
                "name": self.name,
                "size": "%d" % self.size,
                "base_address": "0x%08x" % self.base_address,
                "index": "%d" % self.index,
                "flags": "%d" % self.flags,
            }
            super().__init__(action, signal.SIGTRAP, attributes)

    class SectionLoad(_SectionAction):
        def __init__(self, entries: Dict[bytes, bytes]):
            super().__init__("load module", entries)

    class SectionUnload(_SectionAction):
        def __init__(self, entries: Dict[bytes, bytes]):
            super().__init__("unload module", entries)

    class _RIPBase(StopReason):
        def __init__(self, action: str, entries: Dict[bytes, bytes]):
            self.thread_id: int = rdcp_response.get_int_property(entries, b"thread")
            self.message: Optional[str] = rdcp_response.get_utf_property(
                entries, b"string"
            )

            attributes = {"thread": "%d" % self.thread_id}

            if self.message:
                attributes["message"] = self.message
            super().__init__(action, signal.SIGABRT, attributes)

    class RIP(_RIPBase):
        def __init__(self, entries: Dict[bytes, bytes]):
            super().__init__("RIP", entries)

    class RIPStop(_RIPBase):
        def __init__(self, entries: Dict[bytes, bytes]):
            super().__init__("RIP_STOP", entries)

    class Response(_ProcessedResponse):
        def __init__(self, response: rdcp_response.RDCPResponse):
            super().__init__(response)

            self.stopped: Optional[bool] = None

            if not self.ok:
                return

            self.stopped: bool = self.status == rdcp_response.RDCPResponse.STATUS_OK

            self.reason: Optional[IsStopped.StopReason] = None
            if not self.stopped:
                return

            full_reason = response.data.decode("utf-8")
            reason, info = full_reason.split(" ", 1)

            entries = response.parse_data_map()

            if reason == "stopped":
                self.reason = IsStopped.Unknown()
                return

            if reason == "debugstr":
                self.reason = IsStopped.Debugstr(entries)
                return

            if reason == "assert":
                self.reason = IsStopped.Assertion(entries)
                return

            if reason == "break":
                self.reason = IsStopped.Breakpoint(entries)
                return

            if reason == "singlestep":
                self.reason = IsStopped.SingleStep(entries)
                return

            if reason == "data":
                self.reason = IsStopped.DataBreakpoint(entries)
                return

            if reason == "execution":
                self.reason = IsStopped.ExecutionStateChange(info)
                return

            if reason == "exception":
                self.reason = IsStopped.Exception(entries)
                return

            if reason == "create":
                self.reason = IsStopped.CreateThread(entries)
                return

            if reason == "terminate":
                self.reason = IsStopped.TerminateThread(entries)
                return

            if reason == "modload":
                self.reason = IsStopped.ModuleLoad(entries)
                return

            if reason == "sectload":
                self.reason = IsStopped.SectionLoad(entries)
                return

            if reason == "sectunload":
                self.reason = IsStopped.SectionUnload(entries)
                return

            if reason == "rip":
                self.reason = IsStopped.RIP(entries)
                return

            if reason == "ripstop":
                self.reason = IsStopped.RIPStop(entries)
                return

        @property
        def ok(self) -> bool:
            return (
                self.status == rdcp_response.RDCPResponse.STATUS_OK
                or self.status == rdcp_response.RDCPResponse.STATUS_ERR_NOT_STOPPED
            )

        @property
        def _body_str(self) -> str:
            if self.stopped:
                return f"Stopped: {self.reason}"
            return "Not stopped"

    def __init__(self, thread_id: int, handler=None):
        super().__init__("isstopped", response_class=self.Response, handler=handler)
        self.body = bytes(f" thread={thread_id}", "utf-8")


class IRTSweep(ProcessedCommand):
    """???"""

    class Response(_ProcessedRawBodyResponse):
        pass

    def __init__(self, handler=None):
        super().__init__("irtsweep", response_class=self.Response, handler=handler)


class KernelDebug(ProcessedCommand):
    """Configures the KD."""

    class Mode(enum.Enum):
        ENABLE = b" enable"
        DISABLE = b" disable"
        EXCEPT = b" except"
        EXCEPT_IF = b" exceptif"

    class Response(_ProcessedRawBodyResponse):
        pass

    def __init__(self, mode: Mode, handler=None):
        super().__init__("kd", response_class=self.Response, handler=handler)
        self.body = mode.value


# class KeyExchange(_ProcessedCommand):
#     """???"""
#
#     class Response(_ProcessedRawBodyResponse):
#         pass
#
#     def __init__(self, keydata: bytes, handler=None):
#         super().__init__("keyxchg", response_class=self.Response, handler=handler)
#         self._binary_payload = keydata


class LOP(ProcessedCommand):
    """Profiler command???"""

    class Command(enum.Enum):
        START_EVENT = b" cmd=start event="
        START_COUNTER = b" cmd=start counter="
        STOP = b" cmd=stop"
        INFO = b" cmd=info"

    class Response(_ProcessedRawBodyResponse):
        pass

    def __init__(
        self, command: Command, command_data: Optional[int] = None, handler=None
    ):
        super().__init__("lop", response_class=self.Response, handler=handler)
        self.body = command.value
        if command == self.Command.START_EVENT or command == self.Command.START_COUNTER:
            if not command_data:
                command_data = 0
            self.body += bytes("0x%X" % command_data, "utf-8")


class MagicBoot(ProcessedCommand):
    """Triggers a boot/reboot."""

    class Response(_ProcessedRawBodyResponse):
        pass

    def __init__(
        self,
        title: str,
        enable_xbdm_after_reboot: bool = False,
        enable_cold: bool = False,
        handler=None,
    ):
        super().__init__("magicboot", response_class=self.Response, handler=handler)
        flags = ""
        if enable_xbdm_after_reboot:
            flags += " debug"
        if enable_cold:
            flags += " cold"
        self.body = bytes(f' title="{title}"{flags}', "utf-8")


class MemTrack(ProcessedCommand):
    """???."""

    class Command(enum.Enum):
        ENABLE = b" cmd=enable"  # (stackdepth, flags)
        ENABLE_ONCE = b" cmd=enableonce"  # (stackdepth, flags)
        DISABLE = b" cmd=disable"
        SAVE = b" cmd=save"  # filename
        QUERY_STACK_DEPTH = b" cmd=querystackdepth"
        QUERY_TYPE = b" cmd=querytype"  # type
        QUERY_FLAGS = b" cmd=queryflags"

    class Response(_ProcessedRawBodyResponse):
        pass

    def __init__(
        self,
        command: Command,
        command_args=None,
        handler=None,
    ):
        super().__init__("memtrack", response_class=self.Response, handler=handler)
        self.body = command.value

        if command == self.Command.ENABLE or command == self.Command.ENABLE_ONCE:
            self.body += bytes(" stackdepth=0x%X flags=0x%X" % command_args, "utf-8")
        elif command == self.Command.SAVE:
            self.body += bytes(' filename="%s"' % command_args, "utf-8")
        elif command == self.Command.QUERY_TYPE:
            self.body += bytes(" type=0x%X" % command_args, "utf-8")


class MemoryMapGlobal(ProcessedCommand):
    """Returns info about the global memory map."""

    class Response(_ProcessedResponse):
        def __init__(self, response: rdcp_response.RDCPResponse):
            super().__init__(response)

            self.MmHighestPhysicalPage = None
            self.RetailPfnRegion = None
            self.SystemPteRange = None
            self.AvailablePages = None
            self.AllocatedPagesByUsage = None
            self.PfnDatabase = None
            self.AddressSpaceLock = None
            self.VadRoot = None
            self.VadHint = None
            self.VadFreeHint = None
            self.MmNumberOfPhysicalPages = None
            self.MmAvailablePages = None

            if not self.ok:
                return

            entries = response.parse_data_map()
            self.MmHighestPhysicalPage = rdcp_response.get_int_property(
                entries, b"MmHighestPhysicalPage"
            )
            self.RetailPfnRegion = rdcp_response.get_int_property(
                entries, b"RetailPfnRegion"
            )
            self.SystemPteRange = rdcp_response.get_int_property(
                entries, b"SystemPteRange"
            )
            self.AvailablePages = rdcp_response.get_int_property(
                entries, b"AvailablePages"
            )
            self.AllocatedPagesByUsage = rdcp_response.get_int_property(
                entries, b"AllocatedPagesByUsage"
            )
            self.PfnDatabase = rdcp_response.get_int_property(entries, b"PfnDatabase")
            self.AddressSpaceLock = rdcp_response.get_int_property(
                entries, b"AddressSpaceLock"
            )
            self.VadRoot = rdcp_response.get_int_property(entries, b"VadRoot")
            self.VadHint = rdcp_response.get_int_property(entries, b"VadHint")
            self.VadFreeHint = rdcp_response.get_int_property(entries, b"VadFreeHint")
            self.MmNumberOfPhysicalPages = rdcp_response.get_int_property(
                entries, b"MmNumberOfPhysicalPages"
            )
            self.MmAvailablePages = rdcp_response.get_int_property(
                entries, b"MmAvailablePages"
            )

        @property
        def ok(self):
            return self.status == rdcp_response.RDCPResponse.STATUS_MULTILINE_RESPONSE

        @property
        def _body_str(self) -> str:
            return f"MmHighestPhysicalPage: {self.MmHighestPhysicalPage} RetailPfnRegion: {self.RetailPfnRegion} SystemPteRange: {self.SystemPteRange} AvailablePages: {self.AvailablePages} AllocatedPagesByUsage: {self.AllocatedPagesByUsage} PfnDatabase: {self.PfnDatabase} AddressSpaceLock: {self.AddressSpaceLock} VadRoot: {self.VadRoot} VadHint: {self.VadHint} VadFreeHint: {self.VadFreeHint} MmNumberOfPhysicalPages: {self.MmNumberOfPhysicalPages} MmAvailablePages: {self.MmAvailablePages}"

    def __init__(self, handler=None):
        super().__init__("mmglobal", response_class=self.Response, handler=handler)


class Mkdir(ProcessedCommand):
    """Creates a directory."""

    class Response(_ProcessedRawBodyResponse):
        pass

    def __init__(self, name: str, handler=None):
        super().__init__("mkdir", response_class=self.Response, handler=handler)
        self.body = bytes(f' name="{name}"', "utf-8")


class ModLongName(ProcessedCommand):
    """??? 'no long name available'"""

    class Response(_ProcessedResponse):
        pass

    def __init__(self, name, handler=None):
        super().__init__("modlong", response_class=self.Response, handler=handler)
        self.body = bytes(f' name="{name}"', "utf-8")


class ModSections(ProcessedCommand):
    """Returns information about the sections in the given executable module."""

    class Response(_ProcessedResponse):
        def __init__(self, response: rdcp_response.RDCPResponse):
            super().__init__(response)

            self.sections = []

            if not self.ok:
                return

            known_keys = {
                b"name": ("name", rdcp_response.get_utf_property),
                b"base": ("base_address", rdcp_response.get_int_property),
                b"size": ("size", rdcp_response.get_int_property),
                b"index": ("index", rdcp_response.get_int_property),
                b"flags": ("flags", rdcp_response.get_int_property),
            }

            entries = response.parse_data_map_array()
            for entry in entries:
                module_info = {
                    new_key: mapper(entry, key)
                    for key, (new_key, mapper) in known_keys.items()
                }

                # Treat any unknown values as boolean flags.
                for key, value in entry.items():
                    if key in known_keys:
                        continue
                    module_info[key.decode("utf-8")] = rdcp_response.get_bool_property(
                        entry, key
                    )

                self.sections.append(module_info)

        @property
        def ok(self):
            return self.status == rdcp_response.RDCPResponse.STATUS_MULTILINE_RESPONSE

        @property
        def _body_str(self) -> str:
            return f"{self.sections}"

    def __init__(self, name, handler=None):
        super().__init__("modsections", response_class=self.Response, handler=handler)
        self.body = bytes(f' name="{name}"', "utf-8")


class Modules(ProcessedCommand):
    """Returns the currently running executable modules."""

    class Response(_ProcessedResponse):
        def __init__(self, response: rdcp_response.RDCPResponse):
            super().__init__(response)

            self.modules = []

            if not self.ok:
                return

            known_keys = {
                b"name": ("name", rdcp_response.get_utf_property),
                b"base": ("base_address", rdcp_response.get_int_property),
                b"size": ("size", rdcp_response.get_int_property),
                b"check": ("checksum", rdcp_response.get_int_property),
                b"timestamp": ("timestamp", rdcp_response.get_int_property),
            }

            entries = response.parse_data_map_array()
            for entry in entries:
                module_info = {
                    new_key: mapper(entry, key)
                    for key, (new_key, mapper) in known_keys.items()
                }

                # Treat any unknown values as boolean flags.
                for key, value in entry.items():
                    if key in known_keys:
                        continue
                    module_info[key.decode("utf-8")] = rdcp_response.get_bool_property(
                        entry, key
                    )

                self.modules.append(module_info)

        @property
        def ok(self):
            return self.status == rdcp_response.RDCPResponse.STATUS_MULTILINE_RESPONSE

        @property
        def _body_str(self) -> str:
            return f"{self.modules}"

    def __init__(self, handler=None):
        super().__init__("modules", response_class=self.Response, handler=handler)


class _StopOnBase(ProcessedCommand):
    """Base class for NoStopOn and StopOn"""

    ALL = 0xFFFFFFFF
    CREATETHREAD = 0x01
    FIRST_CHANCE_EXCEPTION = 0x02
    DEBUGSTR = 0x04
    STACKTRACE = 0x08

    def __init__(self, cmd, response_class, events, handler=None):
        super().__init__(cmd, response_class=response_class, handler=handler)
        if events == self.ALL:
            self.body = bytes(f" all", "utf-8")
            return

        flags = []
        if events & self.CREATETHREAD:
            flags.append("createthread")
        if events & self.FIRST_CHANCE_EXCEPTION:
            flags.append("fce")
        if events & self.DEBUGSTR:
            flags.append("debugstr")
        if events & self.STACKTRACE:
            flags.append("stacktrace")
        flags = " ".join(flags)
        self.body = bytes(f" {flags}", "utf-8")


class NoStopOn(_StopOnBase):
    """Clears the events that will break into the debugger."""

    class Response(_ProcessedRawBodyResponse):
        pass

    def __init__(self, events: int = 0xFFFFFFFF, handler=None):
        super().__init__("nostopon", self.Response, events, handler=handler)


class Notify(ProcessedCommand):
    """Registers connection as a notification channel."""

    class Response(_ProcessedResponse):
        pass

    def __init__(self, handler=None):
        super().__init__("notify", response_class=self.Response, handler=handler)
        self._dedicate_notification_mode = True


class NotifyAt(ProcessedCommand):
    """Causes the XBDM to open a new notification connection to the given port."""

    class Response(_ProcessedResponse):
        pass

    def __init__(
        self,
        port: int,
        addr: Optional[str] = None,
        drop_flag: bool = False,
        debug_flag: bool = False,
        handler=None,
    ):
        super().__init__("notifyat", response_class=self.Response, handler=handler)

        self.port = port
        self.address = addr
        self.drop = drop_flag
        self.debug = debug_flag

        flags = ""
        if addr:
            flags += f' addr="{addr}"'
        if drop_flag:
            flags += " drop"
        elif debug_flag:
            flags += " debug"
        self.body = bytes(" port=0x%X%s" % (port, flags), "utf-8")


class PBSnap(ProcessedCommand):
    """Takes a D3D snapshot (binary must be compiled as debug or profile)."""

    class Response(_ProcessedRawBodyResponse):
        pass

    def __init__(self, handler=None):
        super().__init__("pbsnap", response_class=self.Response, handler=handler)


class PerformanceCounterList(ProcessedCommand):
    """Returns the list of performance counters and their types."""

    class Response(_ProcessedRawBodyResponse):
        def __init__(self, response: rdcp_response.RDCPResponse):
            super().__init__(response)

            self.performance_counters = []

            if not self.ok:
                return

            entries = response.parse_data_map_array()
            for entry in entries:
                self.performance_counters.append(
                    {
                        "name": rdcp_response.get_utf_property(entry, b"name"),
                        "type": rdcp_response.get_int_property(entry, b"type"),
                    }
                )

        @property
        def ok(self):
            return self.status == rdcp_response.RDCPResponse.STATUS_MULTILINE_RESPONSE

        @property
        def _body_str(self) -> str:
            return f"{self.performance_counters}"

    def __init__(self, handler=None):
        super().__init__("pclist", response_class=self.Response, handler=handler)


class PDBInfo(ProcessedCommand):
    """Retrieves Program Database information."""

    class Response(_ProcessedRawBodyResponse):
        pass

    def __init__(self, addr, handler=None):
        super().__init__("pdbinfo", response_class=self.Response, handler=handler)
        self.body = bytes(" addr=0x%X" % addr, "utf-8")


class PSSnap(ProcessedCommand):
    """Takes a D3D snapshot (binary must be compiled as debug)."""

    class Response(_ProcessedRawBodyResponse):
        pass

    def __init__(self, x: int, y: int, flags: int = 0, marker: int = 0, handler=None):
        super().__init__("pssnap", response_class=self.Response, handler=handler)
        self.body = bytes(" x=0x%X y=0x%X" % (x, y), "utf-8")
        if flags:
            self.body += b" flags=0x%X" % flags
        if marker:
            self.body += b" marker=0x%X" % marker


class QueryPerformanceCounter(ProcessedCommand):
    """Retrieves performance counter information."""

    class Response(_ProcessedRawBodyResponse):
        pass

    def __init__(self, name, counter_type=None, handler=None):
        super().__init__("querypc", response_class=self.Response, handler=handler)
        if counter_type:
            counter_type = f" type={counter_type}"
        else:
            counter_type = ""

        self.body = bytes(f' name="{name}"{counter_type}', "utf-8")


class Reboot(ProcessedCommand):
    """Triggers a reboot."""

    FLAG_WAIT = 1
    FLAG_WARM = 2
    FLAG_NO_DEBUG = 4
    FLAG_STOP = 8

    class Response(_ProcessedRawBodyResponse):
        pass

    def __init__(self, flags: int = 0, handler=None):
        super().__init__("reboot", response_class=self.Response, handler=handler)
        body = b""
        if flags & self.FLAG_WAIT:
            body += b" wait"
        if flags & self.FLAG_WARM:
            body += b" warm"
        if flags & self.FLAG_NO_DEBUG:
            body += b" nodebug"
        if flags & self.FLAG_STOP:
            body += b" stop"

        if body:
            self.body = body


class Rename(ProcessedCommand):
    """Renames a file or directory."""

    class Response(_ProcessedRawBodyResponse):
        pass

    def __init__(self, name: str, new_name: str, handler=None):
        super().__init__("rename", response_class=self.Response, handler=handler)
        self.body = bytes(' name="%s" newname="%s"' % (name, new_name), "utf-8")


class Resume(ProcessedCommand):
    """Resumes execution of the given thread."""

    class Response(_ProcessedRawBodyResponse):
        pass

    def __init__(self, thread_id: int, handler=None):
        super().__init__("resume", response_class=self.Response, handler=handler)
        self.body = bytes(f" thread={thread_id}", "utf-8")


class Screenshot(ProcessedCommand):
    """Captures a screenshot from the device."""

    class Response(_ProcessedResponse):
        def __init__(self, response: rdcp_response.RDCPResponse):
            super().__init__(response)

            self.printable_data = ""
            self.data = bytes()

            if not self.ok:
                return

            self.printable_data, self.data = response.parse_hex_data()

        @property
        def ok(self):
            return self.status == rdcp_response.RDCPResponse.STATUS_MULTILINE_RESPONSE

        @property
        def _body_str(self) -> str:
            return f"{self.printable_data}"

    def __init__(self, handler=None):
        super().__init__("screenshot", response_class=self.Response, handler=handler)


class SendFile(ProcessedCommand):
    """Uploads a file to the device."""

    class Response(_ProcessedResponse):
        def __init__(self, response: rdcp_response.RDCPResponse):
            super().__init__(response)

            self.printable_data = ""
            self.data = bytes()

            if not self.ok:
                return

            self.printable_data, self.data = response.parse_hex_data()

        @property
        def ok(self):
            return self.status == rdcp_response.RDCPResponse.STATUS_MULTILINE_RESPONSE

        @property
        def _body_str(self) -> str:
            return f"{self.printable_data}"

    def __init__(self, name: str, content: bytes, handler=None):
        super().__init__("sendfile", response_class=self.Response, handler=handler)
        self.body = bytes(' name="%s" length=0x%X' % (name, len(content)), "utf-8")
        self._binary_payload = content


# class ServiceName(_ProcessedCommand):
#     """???"""
#
#     class Response(_ProcessedRawBodyResponse):
#         pass
#
#     def __init__(self, handler=None):
#         super().__init__("servname", response_class=self.Response, handler=handler)
#         # id(int) name(string)
#         # name must begin with one of (prod|part|test)
#         # There's a second mode that looks like it can take a command string that matches some internal state var


class SetConfig(ProcessedCommand):
    """Sets an NVRAM configuration value."""

    class Response(_ProcessedRawBodyResponse):
        pass

    def __init__(self, index: int, value: int, handler=None):
        super().__init__("setconfig", response_class=self.Response, handler=handler)
        self.body = b" index=0x%X value=0x%X" % (index, value)


class SetContext(ProcessedCommand):
    """Sets registers in the active thread context."""

    class Response(_ProcessedRawBodyResponse):
        pass

    def __init__(
        self,
        thread_id: int,
        register_map: Optional[Mapping[str, int]] = None,
        ext: Optional[bytes] = None,
        handler=None,
    ):
        super().__init__("setcontext", response_class=self.Response, handler=handler)
        body = " thread=0x%X " % thread_id
        if ext:
            body += " ext=0x%X" % len(ext)
            self._binary_payload = ext
        if register_map:
            for entry in register_map.items():
                body += " %s=0x%X" % entry
        self.body = bytes(body, "utf-8")


class SetFileAttributes(ProcessedCommand):
    """Sets the attributes of a file."""

    class Response(_ProcessedRawBodyResponse):
        pass

    def __init__(
        self,
        name: str,
        readonly: Optional[bool] = None,
        hidden: Optional[bool] = None,
        create_timestamp: Optional[int] = None,
        change_timestamp: Optional[int] = None,
        handler=None,
    ):
        super().__init__(
            "setfileattributes", response_class=self.Response, handler=handler
        )
        self.body = bytes(f' name="{name}"', "utf-8")
        if readonly is not None:
            readonly = 1 if readonly else 0
            self.body += b" readonly=0x%X" % readonly
        if hidden is not None:
            hidden = 1 if readonly else 0
            self.body += b" hidden=0x%X" % hidden
        if create_timestamp is not None:
            self.body += b" createlo:0x%X createhi:0x%X" % (
                create_timestamp & 0xFFFFFFFF,
                (create_timestamp >> 32) & 0xFFFFFFFF,
            )
        if change_timestamp is not None:
            self.body += b" changelo:0x%X changehi:0x%X" % (
                change_timestamp & 0xFFFFFFFF,
                (change_timestamp >> 32) & 0xFFFFFFFF,
            )


class SetMem(ProcessedCommand):
    """Sets the value of a block of memory."""

    class Response(_ProcessedRawBodyResponse):
        pass

    def __init__(self, addr: int, data: bytes, handler=None):
        super().__init__("setmem", response_class=self.Response, handler=handler)
        self.body = b" addr=0x%X data=" % addr
        self.body += binascii.hexlify(data)


class SetSystemTime(ProcessedCommand):
    """Sets the system time."""

    class Response(_ProcessedRawBodyResponse):
        pass

    def __init__(self, nt_timestamp: int, timezone: Optional[int] = 0, handler=None):
        super().__init__("setsystime", response_class=self.Response, handler=handler)
        self.body = b" clocklo=0x%X clockhi=0x%X" % (
            nt_timestamp & 0xFFFFFFFF,
            (nt_timestamp >> 32) & 0xFFFFFFFF,
        )
        if timezone is not None:
            self.body += b" tz=0x%X" % timezone


class Stop(ProcessedCommand):
    """Stops execution of all threads."""

    class Response(_ProcessedRawBodyResponse):
        pass

    def __init__(self, handler=None):
        super().__init__("stop", response_class=self.Response, handler=handler)


class StopOn(_StopOnBase):
    """Sets the events that will break into the debugger."""

    class Response(_ProcessedRawBodyResponse):
        pass

    def __init__(self, events: int = 0xFFFFFFFF, handler=None):
        super().__init__("stopon", self.Response, events, handler=handler)


class Suspend(ProcessedCommand):
    """Suspends the given thread."""

    class Response(_ProcessedResponse):
        pass

    def __init__(self, thread_id: int, handler=None):
        super().__init__("suspend", response_class=self.Response, handler=handler)
        self.body = bytes(f" thread={thread_id}", "utf-8")


# sysfileupd - Looks like this may be invoking a system update?


class SystemTime(ProcessedCommand):
    """Retrieves the system time."""

    class Response(_ProcessedResponse):
        def __init__(self, response: rdcp_response.RDCPResponse):
            super().__init__(response)

            if not self.ok:
                self.time = None
                return

            entries = response.parse_data_map()
            self.time = rdcp_response.get_qword_property(entries, b"low", b"high")

        @property
        def _body_str(self) -> str:
            return f"{self.time}"

    def __init__(self, handler=None):
        super().__init__("systime", response_class=self.Response, handler=handler)


class ThreadInfo(ProcessedCommand):
    """Gets information about a specific thread."""

    class Response(_ProcessedResponse):
        def __init__(self, response: rdcp_response.RDCPResponse):
            super().__init__(response)

            if not self.ok:
                self.suspend = None
                self.priority = None
                self.tlsbase = None
                self.start = None
                self.base = None
                self.limit = None
                self.create = None
                return

            entries = response.parse_data_map()
            known_keys = {
                b"suspend",
                b"priority",
                b"tlsbase",
                b"start",
                b"base",
                b"limit",
                b"createlo",
                b"createhi",
            }
            self.suspend = rdcp_response.get_bool_property(entries, b"suspend")
            self.priority = rdcp_response.get_int_property(entries, b"priority")
            self.tlsbase = rdcp_response.get_int_property(entries, b"tlsbase")
            self.start = rdcp_response.get_int_property(entries, b"start")
            self.base = rdcp_response.get_int_property(entries, b"base")
            self.limit = rdcp_response.get_int_property(entries, b"limit")
            self.create = rdcp_response.get_qword_property(
                entries, b"createlo", b"createhi"
            )

            unknown_keys = set(entries.keys()) - known_keys
            if unknown_keys:
                logger.error(f"Found unknown thread info: {unknown_keys}")
                assert False

        @property
        def ok(self):
            return self.status == rdcp_response.RDCPResponse.STATUS_MULTILINE_RESPONSE

        @property
        def _body_str(self) -> str:
            return f" suspend={self.suspend} priority={self.priority} tlsbase={self.tlsbase} start={self.start} base={self.base} limit={self.limit} create={self.create}"

    def __init__(self, thread_id: int, handler=None):
        super().__init__("threadinfo", response_class=self.Response, handler=handler)
        self.body = bytes(f" thread={thread_id}", "utf-8")


class Threads(ProcessedCommand):
    """Gets the list of active threads."""

    class Response(_ProcessedResponse):
        def __init__(self, response: rdcp_response.RDCPResponse):
            super().__init__(response)
            lines = response.parse_multiline()
            self.thread_ids = [int(x.decode("utf-8")) for x in lines]

        @property
        def ok(self):
            return self.status == rdcp_response.RDCPResponse.STATUS_MULTILINE_RESPONSE

        @property
        def _body_str(self) -> str:
            return str(self.thread_ids)

    def __init__(self, handler=None):
        super().__init__("threads", response_class=self.Response, handler=handler)


class LoadOnBootTitle(ProcessedCommand):
    """Sets the path to the XBE that will be loaded when rebooting."""

    class Response(_ProcessedRawBodyResponse):
        pass

    def __init__(
        self,
        name: str,
        directory: Optional[str] = None,
        command_line: Optional[str] = None,
        persist: bool = False,
        handler=None,
    ):
        super().__init__("title", response_class=self.Response, handler=handler)
        if not name:
            self.body = b" none"
            return

        body = f' name="{name}"'
        if directory:
            body += f' dir="{directory}"'
        if command_line:
            body += f' cmdline="{command_line}"'
        if persist:
            body += f" persist"

        self.body = bytes(body, "utf-8")


class LoadOnBootTitleUnpersist(ProcessedCommand):
    """Clears the post-reboot title path."""

    class Response(_ProcessedRawBodyResponse):
        pass

    def __init__(self, handler=None):
        super().__init__("title", response_class=self.Response, handler=handler)
        self.body = b" nopersist"


class UserList(ProcessedCommand):
    """Retrieves the registered users (must be locked)."""

    class Response(_ProcessedRawBodyResponse):
        # TODO: Handle response.
        pass

    def __init__(self, handler=None):
        super().__init__("userlist", response_class=self.Response, handler=handler)


class VSSnap(ProcessedCommand):
    """Takes a D3D snapshot (binary must be compiled as debug)."""

    class Response(_ProcessedRawBodyResponse):
        pass

    def __init__(
        self, first: int, last: int, flags: int = 0, marker: int = 0, handler=None
    ):
        super().__init__("vssnap", response_class=self.Response, handler=handler)
        self.body = bytes(" first=0x%X last=0x%X" % (first, last), "utf-8")
        if flags:
            self.body += b" flags=0x%X" % flags
        if marker:
            self.body += b" marker=0x%X" % marker


class WalkMem(ProcessedCommand):
    """Returns a list of valid virtual memory regions."""

    class Response(_ProcessedResponse):
        def __init__(self, response: rdcp_response.RDCPResponse):
            super().__init__(response)

            self.regions = []

            if not self.ok:
                return

            known_keys = {
                b"base": ("base_address", rdcp_response.get_int_property),
                b"size": ("size", rdcp_response.get_int_property),
                b"protect": ("protection_flags", rdcp_response.get_int_property),
            }

            entries = response.parse_data_map_array()
            for entry in entries:
                module_info = {
                    new_key: mapper(entry, key)
                    for key, (new_key, mapper) in known_keys.items()
                }

                # Treat any unknown values as boolean flags.
                for key, value in entry.items():
                    if key in known_keys:
                        continue
                    module_info[key.decode("utf-8")] = rdcp_response.get_bool_property(
                        entry, key
                    )

                self.regions.append(module_info)

        @property
        def ok(self):
            return self.status == rdcp_response.RDCPResponse.STATUS_MULTILINE_RESPONSE

        @property
        def _body_str(self) -> str:
            return f"{self.regions}"

    def __init__(self, handler=None):
        super().__init__("walkmem", response_class=self.Response, handler=handler)


class WriteFile(ProcessedCommand):
    """Writes data into an existing file."""

    class Response(_ProcessedResponse):
        def __init__(self, response: rdcp_response.RDCPResponse):
            super().__init__(response)

            self.printable_data = ""
            self.data = bytes()

            if not self.ok:
                return

            self.printable_data, self.data = response.parse_hex_data()

        @property
        def ok(self):
            return self.status == rdcp_response.RDCPResponse.STATUS_MULTILINE_RESPONSE

        @property
        def _body_str(self) -> str:
            return f"{self.printable_data}"

    def __init__(self, name: str, content: bytes, offset: int = 0, handler=None):
        super().__init__("sendfile", response_class=self.Response, handler=handler)
        self.body = bytes(
            ' name="%s" length=0x%X offset=0x%X' % (name, len(content), offset), "utf-8"
        )
        self._binary_payload = content


class XBEInfo(ProcessedCommand):
    """Retrieves info about an XBE."""

    class Response(_ProcessedResponse):
        def __init__(self, response: rdcp_response.RDCPResponse):
            super().__init__(response)

            if not self.ok:
                self.timestamp = None
                self.checksum = None
                self.name = None
                return

            entries = response.parse_data_map()
            self.timestamp = rdcp_response.get_int_property(entries, b"timestamp")
            self.checksum = rdcp_response.get_int_property(entries, b"checksum")
            self.name = rdcp_response.get_utf_property(entries, b"name")

        @property
        def ok(self):
            return self.status == rdcp_response.RDCPResponse.STATUS_MULTILINE_RESPONSE

        @property
        def _body_str(self) -> str:
            return (
                f" name={self.name} timestamp={self.timestamp} checksum={self.checksum}"
            )

    def __init__(self, name=None, on_disk_only=None, handler=None):
        super().__init__("xbeinfo", response_class=self.Response, handler=handler)
        if not name:
            self.body = bytes(f" running", "utf-8")
        else:
            on_disk_only = " ondiskonly" if on_disk_only else ""
            self.body = bytes(f' name="{name}"{on_disk_only}', "utf-8")


class XTLInfo(ProcessedCommand):
    """Retrieves last error info."""

    class Response(_ProcessedResponse):
        def __init__(self, response: rdcp_response.RDCPResponse):
            super().__init__(response)

            if not self.ok:
                self.lasterr = None
                return

            entries = response.parse_data_map()
            self.lasterr = rdcp_response.get_int_property(entries, b"lasterr")

        @property
        def ok(self):
            return self.status == rdcp_response.RDCPResponse.STATUS_MULTILINE_RESPONSE

        @property
        def _body_str(self) -> str:
            return f" lasterr={self.lasterr}"

    def __init__(self, handler=None):
        super().__init__("xtlinfo", response_class=self.Response, handler=handler)
