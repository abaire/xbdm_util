"""Provides utilities in support of Remote Debugging and Control Protocol."""
import binascii
import enum
import ipaddress
import logging
from typing import Callable
from typing import Dict
from typing import Mapping
from typing import Optional

from . import rdcp_response

logger = logging.getLogger(__name__)


class RDCPCommand:
    """Models a Remote Debugging and Control Protocol command."""

    TERMINATOR = b"\r\n"
    STR_BODY_CUTOFF = 16

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
            return self.alt_ip

    def __init__(self, handler=None):
        super().__init__("altaddr", response_class=self.Response, handler=handler)


class _Break(_ProcessedCommand):
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
        size_string = f"size={size}" if not clear else ""
        self.body = bytes(
            f" {clear_string}{access_type}={address}{size_string}", "utf-8"
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


class Bye(_ProcessedCommand):
    """Closes the connection gracefully."""

    class Response(_ProcessedResponse):
        pass

    def __init__(self, handler=None):
        super().__init__("bye", response_class=self.Response, handler=handler)


class ProfilerCaptureControl(_ProcessedCommand):
    """Starts or stops profiling capture."""

    class Response(_ProcessedRawBodyResponse):
        pass

    def __init__(self, start: bool = True, handler=None):
        super().__init__("capctrl", response_class=self.Response, handler=handler)
        if start:
            self.body = b" start"


class Continue(_ProcessedCommand):
    """Continues execution of the given thread."""

    class Response(_ProcessedResponse):
        pass

    def __init__(self, thread_id, exception: bool = False, handler=None):
        # TODO: Document 'exception' flag behavior.
        super().__init__("continue", response_class=self.Response, handler=handler)
        thread_id_string = "0x%X" % thread_id
        exception_string = " exception" if exception else ""
        self.body = bytes(f" thread={thread_id_string}{exception_string}", "utf-8")


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
            return {self.name}

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

    def __init__(self, handler=None):
        super().__init__("debugmode", response_class=self.Response, handler=handler)


class Dedicate(_ProcessedCommand):
    """Sets connection as dedicated."""

    class Response(_ProcessedRawBodyResponse):
        pass

    def __init__(self, global_enable=None, handler_name=None, handler=None):
        super().__init__("dedicate", response_class=self.Response, handler=handler)
        if global_enable:
            self.body = b" global"
        elif handler_name:
            self.body = bytes(f' handler="{handler_name}"', "utf-8")


class DefTitle(_ProcessedCommand):
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


class Delete(_ProcessedCommand):
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


class DirList(_ProcessedCommand):
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
            return f"version={self.version}"

    def __init__(self, handler=None):
        super().__init__("dmversion", response_class=self.Response, handler=handler)


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
            return f"{self.drives}"

    def __init__(self, handler=None):
        super().__init__("drivelist", response_class=self.Response, handler=handler)


class FuncCall(_ProcessedCommand):
    """??? thread must be stopped, just returns OK"""

    class Response(_ProcessedRawBodyResponse):
        pass

    def __init__(self, thread_id, handler=None):
        super().__init__("funccall", response_class=self.Response, handler=handler)
        self.body = bytes(f" thread={thread_id}", "utf-8")


class GetContext(_ProcessedCommand):
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
            return ", ".join(self.registers.items())

    def __init__(
        self,
        thread_id,
        enable_control=False,
        enable_interrupt=False,
        enable_full=False,
        enable_fp=False,
        handler=None,
    ):
        super().__init__("getcontext", response_class=self.Response, handler=handler)
        thread_id_str = "%d" % thread_id
        flags = []
        if enable_control:
            flags.append("control")
        if enable_interrupt:
            flags.append("int")
        if enable_full:
            flags.append("full")
        if enable_fp:
            flags.append("fp")
        if not flags:
            flags = ""
        else:
            flags = " " + " ".join(flags)
        self.body = bytes(f" thread={thread_id_str}{flags}", "utf-8")


class GetD3DState(_ProcessedCommand):
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


class GetExtContext(_ProcessedCommand):
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

    def __init__(self, thread_id, handler=None):
        super().__init__("getextcontext", response_class=self.Response, handler=handler)
        thread_id_str = "%d" % thread_id
        self.body = bytes(f" thread={thread_id_str}", "utf-8")
        self._binary_response_length = (
            rdcp_response.RDCPResponse.BINARY_FIRST_DWORD_HAS_SIZE
        )


class GetFile(_ProcessedCommand):
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


class GetFileAttributes(_ProcessedCommand):
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


class GetGamma(_ProcessedCommand):
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


class GetMem(_ProcessedCommand):
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


class GetMemBinary(_ProcessedCommand):
    """Gets the contents of a block of memory as a binary chunk."""

    class Response(_ProcessedResponse):
        def __init__(self, response: rdcp_response.RDCPResponse):
            super().__init__(response)

            self.printable_data = ""
            self.data = bytes()

            if not self.ok:
                return

            self.data = response.data
            # TODO: Consider dropping printable_data.
            # The only differentiation between getmem2 and getmem is that this method returns a binary, so converting it back to a hex string goes against the intent.
            self.printable_data = binascii.hexlify(self.data)

        @property
        def ok(self):
            return self.status == rdcp_response.RDCPResponse.STATUS_BINARY_RESPONSE

        @property
        def _body_str(self) -> str:
            return f"{self.printable_data}"

    def __init__(self, addr, length, handler=None):
        super().__init__("getmem2", response_class=self.Response, handler=handler)
        self._binary_response_length = length
        addr = "0x%X" % addr
        length = "0x%X" % length
        self.body = bytes(f" ADDR={addr} LENGTH={length}", "utf-8")


class GetPalette(_ProcessedCommand):
    """Retrieves palette information (D3DINT_GET_PALETTE)."""

    class Response(_ProcessedRawBodyResponse):
        # TODO: Implement. Calling on the dashboard gives an error.
        pass

    def __init__(self, stage: int, handler=None):
        super().__init__("getpalette", response_class=self.Response, handler=handler)
        self.body = bytes(" STAGE=0x%X" % stage, "utf-8")


class GetProcessID(_ProcessedCommand):
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


class GetChecksum(_ProcessedCommand):
    """Returns the checksum for a memory region."""

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

    def __init__(self, addr: int, length: int, blocksize: int, handler=None):
        super().__init__("getsum", response_class=self.Response, handler=handler)
        # BLOCKSIZE < 8 will hang the device.
        assert blocksize >= 8
        self.body = bytes(
            " ADDR=0x%X LENGTH=0x%X BLOCKSIZE=0x%X" % (addr, length, blocksize), "utf-8"
        )
        self._binary_response_length = 384 // blocksize


class GetSurface(_ProcessedCommand):
    """???"""

    class Response(_ProcessedRawBodyResponse):
        pass

    def __init__(self, surface_id: int, handler=None):
        super().__init__("getsurf", response_class=self.Response, handler=handler)
        self.body = bytes(f" id=0x%X" % surface_id, "utf-8")


class GetUserPrivileges(_ProcessedCommand):
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


class GetUtilityDriveInfo(_ProcessedCommand):
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


class Go(_ProcessedCommand):
    """Resumes execution of all threads."""

    class Response(_ProcessedRawBodyResponse):
        pass

    def __init__(self, handler=None):
        super().__init__("go", response_class=self.Response, handler=handler)


class GPUCounter(_ProcessedCommand):
    """Enables or disables GPU performance counters."""

    class Response(_ProcessedResponse):
        pass

    def __init__(self, enable: bool = True, handler=None):
        super().__init__("gpucount", response_class=self.Response, handler=handler)
        self.body = b" enable" if enable else b" disable"


class Halt(_ProcessedCommand):
    """Halts execution of the given thread."""

    class Response(_ProcessedRawBodyResponse):
        pass

    def __init__(self, thread_id, handler=None):
        super().__init__("halt", response_class=self.Response, handler=handler)
        self.body = bytes(f" thread={thread_id}", "utf-8")


class IsBreak(_ProcessedCommand):
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


class IsDebugger(_ProcessedCommand):
    """Checks to see if the debugger is allowed to attach?"""

    class Response(_ProcessedRawBodyResponse):
        pass

    def __init__(self, handler=None):
        super().__init__("isdebugger", response_class=self.Response, handler=handler)


class IsStopped(_ProcessedCommand):
    """Checks to see if the given thread is stopped."""

    class Response(_ProcessedRawBodyResponse):
        # TODO: Process the reason for the stoppage.
        pass

    def __init__(self, thread_id, handler=None):
        super().__init__("isstopped", response_class=self.Response, handler=handler)
        self.body = bytes(f" thread={thread_id}", "utf-8")


class IRTSweep(_ProcessedCommand):
    """???"""

    class Response(_ProcessedRawBodyResponse):
        pass

    def __init__(self, handler=None):
        super().__init__("irtsweep", response_class=self.Response, handler=handler)


class KernelDebug(_ProcessedCommand):
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


class LOP(_ProcessedCommand):
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


class MagicBoot(_ProcessedCommand):
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


class MemTrack(_ProcessedCommand):
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


class MemoryMapGlobal(_ProcessedCommand):
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


class Mkdir(_ProcessedCommand):
    """Creates a directory."""

    class Response(_ProcessedRawBodyResponse):
        pass

    def __init__(self, name: str, handler=None):
        super().__init__("mkdir", response_class=self.Response, handler=handler)
        self.body = bytes(f' name="{name}"', "utf-8")


class ModLongName(_ProcessedCommand):
    """??? 'no long name available'"""

    class Response(_ProcessedResponse):
        pass

    def __init__(self, name, handler=None):
        super().__init__("modlong", response_class=self.Response, handler=handler)
        self.body = bytes(f' name="{name}"', "utf-8")


class ModSections(_ProcessedCommand):
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


class Modules(_ProcessedCommand):
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


class _StopOnBase(_ProcessedCommand):
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


class Notify(_ProcessedCommand):
    """Registers connection as a notification channel."""

    class Response(_ProcessedResponse):
        pass

    def __init__(self, handler=None):
        super().__init__("notify", response_class=self.Response, handler=handler)
        self._dedicate_notification_mode = True


class NotifyAt(_ProcessedCommand):
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


class PBSnap(_ProcessedCommand):
    """Takes a D3D snapshot (binary must be compiled as debug or profile)."""

    class Response(_ProcessedRawBodyResponse):
        pass

    def __init__(self, handler=None):
        super().__init__("pbsnap", response_class=self.Response, handler=handler)


class PerformanceCounterList(_ProcessedCommand):
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


class PDBInfo(_ProcessedCommand):
    """Retrieves Program Database information."""

    class Response(_ProcessedRawBodyResponse):
        pass

    def __init__(self, addr, handler=None):
        super().__init__("pdbinfo", response_class=self.Response, handler=handler)
        self.body = bytes(" addr=0x%X" % addr, "utf-8")


class PSSnap(_ProcessedCommand):
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


class QueryPerformanceCounter(_ProcessedCommand):
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


class Reboot(_ProcessedCommand):
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


class Rename(_ProcessedCommand):
    """Renames a file or directory."""

    class Response(_ProcessedRawBodyResponse):
        pass

    def __init__(self, name: str, new_name: str, handler=None):
        super().__init__("rename", response_class=self.Response, handler=handler)
        self.body = bytes(' name="%s" newname="%s"' % (name, new_name), "utf-8")


class Resume(_ProcessedCommand):
    """Resumes execution of the given thread."""

    class Response(_ProcessedRawBodyResponse):
        pass

    def __init__(self, thread_id, handler=None):
        super().__init__("resume", response_class=self.Response, handler=handler)
        self.body = bytes(f" thread={thread_id}", "utf-8")


class Screenshot(_ProcessedCommand):
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


class SendFile(_ProcessedCommand):
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


class SetConfig(_ProcessedCommand):
    """Sets an NVRAM configuration value."""

    class Response(_ProcessedRawBodyResponse):
        pass

    def __init__(self, index: int, value: int, handler=None):
        super().__init__("setconfig", response_class=self.Response, handler=handler)
        self.body = b" index=0x%X value=0x%X" % (index, value)


class SetContext(_ProcessedCommand):
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


class SetFileAttributes(_ProcessedCommand):
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


class SetMem(_ProcessedCommand):
    """Sets the value of a block of memory."""

    class Response(_ProcessedRawBodyResponse):
        pass

    def __init__(self, addr: int, data: bytes, handler=None):
        super().__init__("setmem", response_class=self.Response, handler=handler)
        self.body = b" addr=0x%X data=" % addr
        self.body += binascii.hexlify(data)


class SetSystemTime(_ProcessedCommand):
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


class Stop(_ProcessedCommand):
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


class Suspend(_ProcessedCommand):
    """Suspends the given thread."""

    class Response(_ProcessedResponse):
        pass

    def __init__(self, thread_id, handler=None):
        super().__init__("suspend", response_class=self.Response, handler=handler)
        self.body = bytes(f" thread={thread_id}", "utf-8")


# sysfileupd - Looks like this may be invoking a system update?


class SystemTime(_ProcessedCommand):
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


class ThreadInfo(_ProcessedCommand):
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

    def __init__(self, thread_id, handler=None):
        super().__init__("threadinfo", response_class=self.Response, handler=handler)
        self.body = bytes(f" thread={thread_id}", "utf-8")


class Threads(_ProcessedCommand):
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


class LoadOnBootTitle(_ProcessedCommand):
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


class LoadOnBootTitleUnpersist(_ProcessedCommand):
    """Clears the post-reboot title path."""

    class Response(_ProcessedRawBodyResponse):
        pass

    def __init__(self, handler=None):
        super().__init__("title", response_class=self.Response, handler=handler)
        self.body = b" nopersist"


class UserList(_ProcessedCommand):
    """Retrieves the registered users (must be locked)."""

    class Response(_ProcessedRawBodyResponse):
        # TODO: Handle response.
        pass

    def __init__(self, handler=None):
        super().__init__("userlist", response_class=self.Response, handler=handler)


class VSSnap(_ProcessedCommand):
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


class WalkMem(_ProcessedCommand):
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


class WriteFile(_ProcessedCommand):
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


class XBEInfo(_ProcessedCommand):
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


class XTLInfo(_ProcessedCommand):
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
