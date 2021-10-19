"""Provides utilities in support of Remote Debugging and Control Protocol."""
import binascii
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
        self._binary_response_length = 0

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

        body = self._body_str
        if body:
            body = f" {body}"

        ret = f"{self.__class__.__qualname__}::{self._status}:{message}{body}"
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
            return self._status == rdcp_response.RDCPResponse.STATUS_MULTILINE_RESPONSE

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
            return {self.drives}

    def __init__(self, handler=None):
        super().__init__("drivelist", response_class=self.Response, handler=handler)


class GetContext(_ProcessedCommand):
    """???"""

    class Response(_ProcessedRawBodyResponse):
        # Response should be multiline but is always empty in dashboard case.
        pass

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
            return self._status == rdcp_response.RDCPResponse.STATUS_MULTILINE_RESPONSE

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
            return self._status == rdcp_response.RDCPResponse.STATUS_BINARY_RESPONSE

        @property
        def _body_str(self) -> str:
            return f"{self.printable_data}"

    def __init__(self, addr, length, handler=None):
        super().__init__("getmem2", response_class=self.Response, handler=handler)
        self._binary_response_length = length
        addr = "0x%X" % addr
        length = "0x%X" % length
        self.body = bytes(f" ADDR={addr} LENGTH={length}", "utf-8")


class Go(_ProcessedCommand):
    """Resumes execution of all threads."""

    class Response(_ProcessedRawBodyResponse):
        pass

    def __init__(self, handler=None):
        super().__init__("go", response_class=self.Response, handler=handler)


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
        def __init__(self, response: rdcp_response.RDCPResponse):
            super().__init__(response)

            self.type = None

            if not self.ok:
                return

            entries = response.parse_data_map()
            self.type = rdcp_response.get_int_property(entries, b"type")

        @property
        def _body_str(self) -> str:
            return f"type: {self.type}"

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
            return self._status == rdcp_response.RDCPResponse.STATUS_MULTILINE_RESPONSE

        @property
        def _body_str(self) -> str:
            return f"MmHighestPhysicalPage: {self.MmHighestPhysicalPage} RetailPfnRegion: {self.RetailPfnRegion} SystemPteRange: {self.SystemPteRange} AvailablePages: {self.AvailablePages} AllocatedPagesByUsage: {self.AllocatedPagesByUsage} PfnDatabase: {self.PfnDatabase} AddressSpaceLock: {self.AddressSpaceLock} VadRoot: {self.VadRoot} VadHint: {self.VadHint} VadFreeHint: {self.VadFreeHint} MmNumberOfPhysicalPages: {self.MmNumberOfPhysicalPages} MmAvailablePages: {self.MmAvailablePages}"

    def __init__(self, handler=None):
        super().__init__("mmglobal", response_class=self.Response, handler=handler)


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
            return self._status == rdcp_response.RDCPResponse.STATUS_MULTILINE_RESPONSE

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
            return self._status == rdcp_response.RDCPResponse.STATUS_MULTILINE_RESPONSE

        @property
        def _body_str(self) -> str:
            return f"{self.modules}"

    def __init__(self, handler=None):
        super().__init__("modules", response_class=self.Response, handler=handler)


class _StopOnBase(_ProcessedCommand):
    """Base class for NoStopOn and StopOn"""

    ALL = 0xFFFFFFFF
    CREATETHREAD = 0x01
    FCE = 0x02
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
        if events & self.FCE:
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
            return self._status == rdcp_response.RDCPResponse.STATUS_MULTILINE_RESPONSE

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


class Resume(_ProcessedCommand):
    """Resumes execution of the given thread."""

    class Response(_ProcessedRawBodyResponse):
        pass

    def __init__(self, thread_id, handler=None):
        super().__init__("resume", response_class=self.Response, handler=handler)
        self.body = bytes(f" thread={thread_id}", "utf-8")


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


class Systime(_ProcessedCommand):
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
            self.suspend = rdcp_response.get_bool_property(entries, b"suspend")
            self.priority = rdcp_response.get_int_property(entries, b"priority")
            self.tlsbase = rdcp_response.get_int_property(entries, b"tlsbase")
            self.start = rdcp_response.get_int_property(entries, b"start")
            self.base = rdcp_response.get_int_property(entries, b"base")
            self.limit = rdcp_response.get_int_property(entries, b"limit")
            self.create = rdcp_response.get_qword_property(
                entries, b"createlo", b"createhi"
            )

        @property
        def ok(self):
            return self._status == rdcp_response.RDCPResponse.STATUS_MULTILINE_RESPONSE

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
        def _body_str(self) -> str:
            return str(self.thread_ids)

    def __init__(self, handler=None):
        super().__init__("threads", response_class=self.Response, handler=handler)


# class Title(_ProcessedCommand):
#     """???"""
#
#     class Response(_ProcessedResponse):
#         def __init__(self, response: rdcp_response.RDCPResponse):
#             super().__init__(response)
#             lines = response.parse_multiline()
#             self.thread_ids = [int(x.decode("utf-8")) for x in lines]
#
#         @property
#         def _body_str(self) -> str:
#             return str(self.thread_ids)
#
#     def __init__(self, handler=None):
#         super().__init__("threads", response_class=self.Response, handler=handler)
#         # [nopersist]
#         # [dir]
#         # [persist]
#         # name
#         # cmdline


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
            return self._status == rdcp_response.RDCPResponse.STATUS_MULTILINE_RESPONSE

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
            return self._status == rdcp_response.RDCPResponse.STATUS_MULTILINE_RESPONSE

        @property
        def _body_str(self) -> str:
            return f" lasterr={self.lasterr}"

    def __init__(self, handler=None):
        super().__init__("xtlinfo", response_class=self.Response, handler=handler)
