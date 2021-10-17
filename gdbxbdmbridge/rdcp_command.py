"""Provides utilities in support of Remote Debugging and Control Protocol."""


class RDCPCommand:
    """Models a Remote Debugging and Control Protocol command."""

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
        "systime",
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

    TERMINATOR = b"\r\n"

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
            print(f"Received non RDCP packet {buffer}: {buffer[3]} != '-'")
            return -1

        status = buffer[:3]
        self.status = int(status)
        self.data = buffer[4:terminator]

        print(self)
        return terminator + len(self.TERMINATOR)
