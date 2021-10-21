import enum
import sys
import textwrap
from typing import Optional

import natsort

from gdbxbdmbridge import rdcp_command
from gdbxbdmbridge.bridge import GDBXBDMBridge


def _break(args: [str]) -> Optional[rdcp_command.RDCPCommand]:
    if not args:
        return rdcp_command.BreakNow(handler=print)

    mode = args[0].lower()
    if mode == "now":
        return rdcp_command.BreakNow(handler=print)

    if mode == "start":
        return rdcp_command.BreakAtStart(handler=print)

    if mode == "clearall":
        return rdcp_command.BreakClearAll(handler=print)

    clear = False
    if mode[0] == "-":
        mode = mode[1:]

    if mode == "addr" or mode == "address" or mode == "a":
        address = int(args[1], 0)
        return rdcp_command.BreakAtAddress(address, clear, handler=print)

    if mode == "r" or mode == "read":
        address = int(args[1], 0)
        if len(args) > 2:
            size = int(args[2], 0)
        else:
            size = 0
        return rdcp_command.BreakOnRead(address, size, clear, handler=print)

    if mode == "w" or mode == "write":
        address = int(args[1], 0)
        if len(args) > 2:
            size = int(args[2], 0)
        else:
            size = 0
        return rdcp_command.BreakOnWrite(address, size, clear, handler=print)

    if mode == "exec" or mode == "execute" or mode == "e":
        address = int(args[1], 0)
        if len(args) > 2:
            size = int(args[2], 0)
        else:
            size = 0
        return rdcp_command.BreakOnExecute(address, size, clear, handler=print)

    print("Invalid mode")
    return None


def _continue(args) -> Optional[rdcp_command.RDCPCommand]:
    thread_id = int(args[0], 0)
    exception = len(args) > 1
    return rdcp_command.Continue(
        thread_id=thread_id, exception=exception, handler=print
    )


def _debug_options(args) -> Optional[rdcp_command.RDCPCommand]:
    enable_crashdump = None
    enable_dpctrace = None

    for arg in args:
        arg = arg.lower()
        if arg[1] == "c":
            enable_crashdump = arg[0] == "+"
        elif arg[1] == "d":
            enable_dpctrace = arg[0] == "+"

    return rdcp_command.DbgOptions(
        enable_crashdump=enable_crashdump,
        enable_dpctrace=enable_dpctrace,
        handler=print,
    )


def _debugger(args) -> Optional[rdcp_command.RDCPCommand]:
    connect = not args or args[0].lower() != "d"
    return rdcp_command.Debugger(connect, handler=print)


def _dirlist(args) -> Optional[rdcp_command.RDCPCommand]:
    def _print_dir_list(response: rdcp_command.DirList.Response):
        if not response.ok:
            print(response.pretty_message)
            return

        directories = []
        files = []
        for entry in response.entries:
            if entry["directory"]:
                directories.append(entry)
            else:
                files.append(entry)

        directories = natsort.natsorted(
            directories, key=lambda x: x["name"], alg=natsort.ns.IGNORECASE
        )
        files = natsort.natsorted(
            files, key=lambda x: x["name"], alg=natsort.ns.IGNORECASE
        )

        for entry in directories:
            print(f"           {entry['name']}\\")

        for entry in files:
            print("%10d %s" % (entry["filesize"], entry["name"]))

    # Prevent access denied errors when trying to list the base of a drive path.
    if args[0] and args[0][-1] == ":":
        args[0] += "\\"

    return rdcp_command.DirList(args[0], handler=_print_dir_list)


def _get_context(args) -> Optional[rdcp_command.RDCPCommand]:
    thread_id = int(args[0], 0)

    enable_control = False
    enable_interrupt = False
    enable_full = False
    enable_fp = False

    for arg in args[1:]:
        arg = arg.lower()
        if arg == "control":
            enable_control = True
        elif arg == "int":
            enable_interrupt = True
        elif arg == "full":
            enable_full = True
        elif arg == "fp":
            enable_fp = True
    return rdcp_command.GetContext(
        thread_id,
        enable_control,
        enable_interrupt,
        enable_full,
        enable_fp,
        handler=print,
    )


def _kernel_debug(args: [str]) -> Optional[rdcp_command.RDCPCommand]:
    if not args or args[0] == "+":
        return rdcp_command.KernelDebug(
            rdcp_command.KernelDebug.Mode.ENABLE, handler=print
        )

    if args[0] == "-":
        return rdcp_command.KernelDebug(
            rdcp_command.KernelDebug.Mode.DISABLE_EXCEPT, handler=print
        )

    if args[0] == "-?":
        return rdcp_command.KernelDebug(
            rdcp_command.KernelDebug.Mode.DISABLE_EXCEPT_IF, handler=print
        )

    print("Invalid mode. Must be one of [+, -, -?]")
    return None


def _magic_boot(args: [str]) -> Optional[rdcp_command.RDCPCommand]:
    title = args[0]

    enable_wait_for_debugger = False
    enable_cold = False

    for arg in args[1:]:
        arg = arg.lower()
        if arg[0] == "w":
            enable_wait_for_debugger = True
        elif arg[0] == "c":
            enable_cold = True

    return rdcp_command.MagicBoot(
        title, enable_wait_for_debugger, enable_cold, handler=print
    )


def _no_stop_on(args: [str]) -> Optional[rdcp_command.RDCPCommand]:
    if args:
        events = int(args[0], 0)
    else:
        events = 0xFFFFFFFF

    return rdcp_command.NoStopOn(events, handler=print)


def _set_context(args: [str]) -> Optional[rdcp_command.RDCPCommand]:
    thread_id = int(args[0], 0)
    ext = None
    if len(args) > 1:
        ext = int(args[1], 0)

    return rdcp_command.SetContext(thread_id, ext, handler=print)


def _reboot(args: [str]) -> Optional[rdcp_command.RDCPCommand]:
    modes = {
        "wait": rdcp_command.Reboot.FLAG_WAIT,
        "warm": rdcp_command.Reboot.FLAG_WARM,
        "nodebug": rdcp_command.Reboot.FLAG_NO_DEBUG,
        "stop": rdcp_command.Reboot.FLAG_STOP,
    }

    mode = modes.get(args[0].lower() if args else None)
    if not mode:
        return rdcp_command.Reboot(handler=print)

    return rdcp_command.Reboot(mode, handler=print)


def _walk_memory(_args) -> Optional[rdcp_command.RDCPCommand]:
    def _PrintMemoryWalk(response: rdcp_command.WalkMem.Response):
        response.regions.sort(key=lambda x: x["base_address"])
        for region in response.regions:
            print(
                "Base address: 0x%08X  size: %8d  protection: 0x%X"
                % (
                    region["base_address"],
                    region["size"],
                    region["protection_flags"],
                )
            )

    return rdcp_command.WalkMem(handler=_PrintMemoryWalk)


def _xbe_info(args: [str]) -> Optional[rdcp_command.RDCPCommand]:
    if not args:
        return rdcp_command.XBEInfo(handler=print)

    on_disk_only = len(args) > 1
    rdcp_command.XBEInfo(args[0], on_disk_only, handler=print)


DISPATCH_TABLE = {
    "altaddr": lambda _: rdcp_command.AltAddr(handler=print),
    "break": _break,
    "continue": _continue,
    "debugoptions": _debug_options,
    "debugger": _debugger,
    "debugmode": lambda _: rdcp_command.DebugMode(handler=print),
    "rm": lambda args: rdcp_command.Delete(args[0], args[0][-1] == "/", handler=print),
    "ls": _dirlist,
    "dmversion": lambda _: rdcp_command.DMVersion(handler=print),
    "df": lambda args: rdcp_command.DriveFreeSpace(args[0][0], handler=print),
    "drivelist": lambda _: rdcp_command.DriveList(handler=print),
    # FuncCall
    "getcontext": _get_context,
    "getd3dstate": lambda _: rdcp_command.GetD3DState(handler=print),
    "getextcontext": lambda args: rdcp_command.GetExtContext(
        int(args[0], 0), handler=print
    ),
    # GetFile
    "getfileattr": lambda args: rdcp_command.GetFileAttributes(args[0], handler=print),
    "getgamma": lambda _: rdcp_command.GetGamma(handler=print),
    "getmem": lambda args: rdcp_command.GetMem(
        int(args[0], 0), int(args[1], 0), handler=print
    ),
    # GetMemBinary
    "getpalette": lambda args: rdcp_command.GetPalette(args[0], handler=print),
    "getpid": lambda _: rdcp_command.GetProcessID(handler=print),
    "getchecksum": lambda args: rdcp_command.GetChecksum(
        int(args[0], 0), int(args[1], 0), int(args[2], 0), handler=print
    ),
    "getsurface": lambda args: rdcp_command.GetSurface(args[0], handler=print),
    # GetUserPrivileges
    "getutilitydriveinfo": lambda _: rdcp_command.GetUtilityDriveInfo(handler=print),
    "go": lambda _: rdcp_command.Go(handler=print),
    # GPUCounter
    "halt": lambda args: rdcp_command.Halt(int(args[0], 0), handler=print),
    "isbreak": lambda args: rdcp_command.IsBreak(int(args[0], 0), handler=print),
    "isdebugger": lambda _: rdcp_command.IsDebugger(handler=print),
    "isstopped": lambda args: rdcp_command.IsStopped(int(args[0], 0), handler=print),
    "irtsweep": lambda _: rdcp_command.IRTSweep(handler=print),
    "kd": _kernel_debug,
    # LOP
    "run": _magic_boot,
    # MemTrack
    "memorymap": lambda _: rdcp_command.MemoryMapGlobal(handler=print),
    "mkdir": lambda args: rdcp_command.Mkdir(args[0], handler=print),
    "modlongname": lambda args: rdcp_command.ModLongName(args[0], handler=print),
    "modsections": lambda args: rdcp_command.ModSections(args[0], handler=print),
    "modules": lambda _: rdcp_command.Modules(handler=print),
    "nostopon": _no_stop_on,
    "notify": lambda _: rdcp_command.Notify(handler=print),
    "notifyat": lambda _: rdcp_command.NotifyAt(handler=print),
    # PBSnap
    "performancecounterlist": lambda _: rdcp_command.PerformanceCounterList(
        handler=print
    ),
    # PDBInfo
    # PSSnap
    # QueryPerformanceCounter
    "mv": lambda args: rdcp_command.Rename(args[0], args[1], handler=print),
    "reboot": _reboot,
    "resume": lambda args: rdcp_command.Resume(args[0], handler=print),
    # Screenshot
    # SendFile
    # SetConfig
    "setcontext": _set_context,
    # SetFileAttributes
    # SetMem
    # SetSystemTime
    "stop": lambda _: rdcp_command.Stop(handler=print),
    "stopon": lambda args: rdcp_command.StopOn(int(args[0], 0), handler=print),
    "suspend": lambda args: rdcp_command.Suspend(int(args[0], 0), handler=print),
    "systemtime": lambda _: rdcp_command.SystemTime(handler=print),
    "threadinfo": lambda args: rdcp_command.ThreadInfo(int(args[0], 0), handler=print),
    "threads": lambda _: rdcp_command.Threads(handler=print),
    # UserList
    # VSSnap
    "walk_mem": _walk_memory,
    # WriteFile
    "xbeinfo": _xbe_info,
    "xtlinfo": lambda _: rdcp_command.XTLInfo(handler=print),
    "shell": None,
}


def execute_command(command, command_args, bridge: GDBXBDMBridge) -> int:
    processor = DISPATCH_TABLE.get(command)
    if not processor:
        print("Invalid command")
        return 1

    cmd = processor(command_args)
    if cmd:
        bridge.send_rdcp_command(cmd)

    return 0


class Shell:
    class Result(enum.Enum):
        NOT_HANDLED = 0
        HANDLED = 1
        EXIT_REQUESTED = 2

    def __init__(self, bridge: GDBXBDMBridge):
        self._bridge = bridge

        self._shell_commands = {
            "exit": "Terminate the connection and exit.",
            "quit": "Terminate the connection and exit.",
            "q": "Terminate the connection and exit.",
            "?": "Print help.",
            "help": "Print help.",
            "h": "Print help.",
            "reconnect": "Attempt to reconnect to XBDM.",
        }

    def run(self):
        self._print_prompt()

        for line in sys.stdin:
            line = line.strip().split(" ")
            if not line:
                break

            command = line[0].lower()
            args = line[1:]

            result = self._handle_shell_command(command, args)

            if result == self.Result.EXIT_REQUESTED:
                break
            if result == self.Result.NOT_HANDLED:
                try:
                    execute_command(command, args, self._bridge)
                except IndexError:
                    print("Missing required parameter.")
                except ConnectionResetError:
                    print("Connection closed by XBOX")
                    if not self._attempt_reconnect():
                        print("Failed to reconnect")
                        break

            self._bridge.await_empty_queue()
            self._print_prompt()

    def _print_prompt(self) -> None:
        print("> ", end="")
        sys.stdout.flush()

    def _handle_shell_command(self, command: str, args: [str]) -> Result:
        if not command or command == "help" or command == "?" or command == "h":
            self._print_help(args)
            return self.Result.HANDLED

        if command == "reconnect":
            if not self._attempt_reconnect():
                print("Failed to reconnect.")
            else:
                print("Connected")
            return self.Result.HANDLED

        if command.startswith("exit") or command.startswith("quit"):
            return self.Result.EXIT_REQUESTED

        return self.Result.NOT_HANDLED

    def _print_help(self, _args: [str]):
        commands = sorted([k for k, v in DISPATCH_TABLE.items() if v])
        print("XBDM commands:")
        print(textwrap.fill(", ".join(commands), 80))
        print("\nShell commands:")
        print(textwrap.fill(", ".join(sorted(self._shell_commands.keys()))))

    def _attempt_reconnect(self) -> bool:
        self._bridge.reconnect()
        for i in range(10):
            if self._bridge.connect_xbdm():
                return True
        return False
