"""Provides utilities in support of Remote Debugging and Control Protocol."""
import logging
from typing import Callable

from . import rdcp_response

logger = logging.getLogger(__name__)


class RDCPCommand:
    """Models a Remote Debugging and Control Protocol command."""

    TERMINATOR = b"\r\n"

    COMMANDS = {
        "adminpw",
        "altaddr",
        "authuser",
        "boxid",
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

        if self.command not in self.COMMANDS:
            logger.error(f"Invalid command {command}")
            self.command = None
            return

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
