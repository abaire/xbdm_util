"""Provides wrappers around low-level XBDM commands."""
import binascii
from typing import Optional

import natsort

from xbdm import rdcp_command


def _parse_int_expression(addr_str: str) -> int:
    """Parses the given string as an expression that evaluates to an integer. NO INPUT SANITIZING IS PERFORMED."""
    try:
        return int(eval(addr_str))
    except:
        return 0


def _altaddr(_args: [str]) -> Optional[rdcp_command.RDCPCommand]:
    """

    Prints 'Game Configuration' IP information."""
    return rdcp_command.AltAddr(handler=print)


def _break(args: [str]) -> Optional[rdcp_command.RDCPCommand]:
    """<subcommand> [subcommand_args]

    Adds or removes a breakpoint.

    subcommands:
      clearall - Clears all breakpoints
      start - Sets a breakpoint at program entry. Only valid if the remote is in state "execution pending".
      [-]addr <address> - Breaks on execution at the given address.
      [-]read <address> <length> - Breaks on read access to the given memory range.
      [-]write <address> <length> - Breaks on write access to the given memory range.
      [-]execute <address> <length> - Breaks on execution within the given memory range.

    Subcommands with [-] can be prefixed with '-' to disable a previously set breakpoint.
    E.g., addr 0x12345   # sets a breakpoint at 0x12345
          -addr 0x12345  # clears the breakpoint
    """

    def _print_with_message(response):
        print(f"{response}\n{response.raw_body.decode('utf-8')}")

    if not args:
        # This will break within the XBDM process which will cause XBDM to stop listening for continue events, causing a deadlock.
        return None

    mode = args[0].lower()
    # This will break within the XBDM process which will cause XBDM to stop listening for continue events, causing a deadlock.
    # if mode == "now":
    #     return rdcp_command.BreakNow(handler=_print_with_message)

    if mode == "start":
        return rdcp_command.BreakAtStart(handler=_print_with_message)

    if mode == "clearall":
        return rdcp_command.BreakClearAll(handler=_print_with_message)

    clear = False
    if mode[0] == "-":
        mode = mode[1:]

    if mode == "addr" or mode == "address" or mode == "a":
        address = _parse_int_expression(args[1])
        return rdcp_command.BreakAtAddress(address, clear, handler=_print_with_message)

    if mode == "r" or mode == "read":
        address = _parse_int_expression(args[1])
        if len(args) > 2:
            size = int(args[2], 0)
        else:
            size = 1
        return rdcp_command.BreakOnRead(
            address, size, clear, handler=_print_with_message
        )

    if mode == "w" or mode == "write":
        address = _parse_int_expression(args[1])
        if len(args) > 2:
            size = int(args[2], 0)
        else:
            size = 1
        return rdcp_command.BreakOnWrite(
            address, size, clear, handler=_print_with_message
        )

    if mode == "exec" or mode == "execute" or mode == "e":
        address = _parse_int_expression(args[1])
        if len(args) > 2:
            size = int(args[2], 0)
        else:
            size = 1
        return rdcp_command.BreakOnExecute(
            address, size, clear, handler=_print_with_message
        )

    print("Invalid mode")
    return None


def _continue(args) -> Optional[rdcp_command.RDCPCommand]:
    """<thread_id>

    Continues execution of the given thread.
    """
    thread_id = int(args[0], 0)
    exception = len(args) > 1
    return rdcp_command.Continue(
        thread_id=thread_id, exception=exception, handler=print
    )


def _debug_options(args) -> Optional[rdcp_command.RDCPCommand]:
    """[crashdump | dpctrace] [...]

    If no arguments are given, retrieves the currently active debug options.
    If at least one argument is given, enables that debug option and disables any options that are not given.
    """
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
    """[disable]

    If no args are given, notifies XBDM that this channel intends to act as a debugger.
    If 'disable' is given, disables the previously set debugger flag.
    """
    connect = not args or args[0][0].lower() != "d"
    return rdcp_command.Debugger(connect, handler=print)


def _dedicate(args) -> Optional[rdcp_command.RDCPCommand]:
    """<type>

    Makes this a dedicated communication channel.
    type:
        'global' - Use the global dedicated pool.
        <handler> - Use the `handler` dedicated pool.
    """
    global_enable = None
    handler_name = None

    if args[0].lower() == "global":
        global_enable = True
    else:
        handler_name = args[0]

    return rdcp_command.Dedicate(global_enable, handler_name, handler=print)


def _dirlist(args) -> Optional[rdcp_command.RDCPCommand]:
    """<path>

    Returns a list of items in `path`
    """

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
    """<thread_id> [<mode> [...]]

    Retrieves information about the registers for `thread_id`

    thread_id - The thread to retrieve information about
    mode - [control | int | fp | full]
      Optional list of one or more registry sets to query. If no `mode` is passed,
      all types are queried.
    """
    thread_id = int(args[0], 0)

    if not args[1:]:
        enable_control = True
        enable_integer = True
        enable_floatingpoint = True
    else:
        enable_control = False
        enable_integer = False
        enable_floatingpoint = False

        for arg in args[1:]:
            arg = arg.lower()
            if arg == "control":
                enable_control = True
            elif arg == "int":
                enable_integer = True
            elif arg == "fp":
                enable_floatingpoint = True

    return rdcp_command.GetContext(
        thread_id,
        enable_control,
        enable_integer,
        enable_floatingpoint,
        handler=print,
    )


def _get_mem(args: [str]) -> Optional[rdcp_command.RDCPCommand]:
    """<address> <size>

    Fetches the context of the given block of memory.
    """
    address = _parse_int_expression(args[0])
    return rdcp_command.GetMem(address, int(args[1], 0), handler=print)


def _halt(args: [str]) -> Optional[rdcp_command.RDCPCommand]:
    """[thread_id]

    Halts the given thread, or all threads if no `thread_id` is given.
    """

    if args:
        return rdcp_command.Halt(int(args[0], 0), handler=print)
    rdcp_command.Halt(handler=print)


def _kernel_debug(args: [str]) -> Optional[rdcp_command.RDCPCommand]:
    """[mode]

    Enables or disables the kernel debugger (serial port only)
    """
    mode = rdcp_command.KernelDebug.Mode.ENABLE
    if args:
        args[0] = args[0].lower()
        if args[0].startswith("disable"):
            mode = rdcp_command.KernelDebug.Mode.DISABLE
        elif args[0] == "except":
            mode = rdcp_command.KernelDebug.Mode.EXCEPT
        elif args[0] == "exceptif":
            mode = rdcp_command.KernelDebug.Mode.EXCEPT_IF

    return rdcp_command.KernelDebug(mode, handler=print)


def _magic_boot(args: [str]) -> Optional[rdcp_command.RDCPCommand]:
    """<path> [option [...]]

    Launches the given XBE.

    path - Full path to an XBE to launch.
    option - [nodebug | cold]
      nodebug - Disables XBDM when launching.
      cold - Hard reboots the system before launching.
    """
    title = args[0]

    keep_debugger_resident = True
    enable_cold = False

    for arg in args[1:]:
        arg = arg.lower()
        if arg[0] == "n":
            keep_debugger_resident = False
        elif arg[0] == "c":
            enable_cold = True

    return rdcp_command.MagicBoot(
        title, keep_debugger_resident, enable_cold, handler=print
    )


def _modules(_args) -> Optional[rdcp_command.RDCPCommand]:
    def _print_modules(response: rdcp_command.Modules.Response):
        response.modules.sort(key=lambda x: x["name"])
        for module in response.modules:
            flags = ""
            for flag in {"tls", "xbe"}:
                if module.get(flag):
                    flags += " %s" % flag

            print(
                "Name: %-18s Base address: 0x%08X  size: %8d%s"
                % (module["name"], module["base_address"], module["size"], flags)
            )

    return rdcp_command.Modules(handler=_print_modules)


def _no_stop_on(args: [str]) -> Optional[rdcp_command.RDCPCommand]:
    """<flag> [<flag> [...]] Disables automatic stop on events.

    flag:
      all          - All events
      fce          - First chance exceptions
      debugstr     - debugstr() invocations
      createthread - Thread creation
      stacktrace   - Stack traces
    """
    if args:
        events = 0
        for arg in args:
            arg = arg.lower()
            if arg == "all":
                events = 0xFFFFFFFF
                break

            if arg == "fce":
                events |= rdcp_command.StopOn.FIRST_CHANCE_EXCEPTION
            elif arg == "debugstr":
                events |= rdcp_command.StopOn.DEBUGSTR
            elif arg == "createthread":
                events |= rdcp_command.StopOn.CREATETHREAD
            elif arg == "stacktrace":
                events |= rdcp_command.StopOn.STACKTRACE
    else:
        events = 0xFFFFFFFF

    return rdcp_command.NoStopOn(events, handler=print)


def _notifyat(args: [str]) -> Optional[rdcp_command.RDCPCommand]:
    port = int(args[0], 0)

    drop = False
    debug = False
    addr = None
    i = 1
    while i < len(args):
        arg = args[i].lower()
        if arg == "drop":
            drop = True
        elif arg == "debug":
            debug = True
        elif arg[0] == "a":
            i += 1
            addr = args[i]

        i += 1

    return rdcp_command.NotifyAt(port, addr, drop, debug, handler=print)


def _set_context(args: [str]) -> Optional[rdcp_command.RDCPCommand]:
    thread_id = int(args[0], 0)

    registers = {}
    ext = None

    i = 1
    while i < len(args):
        if args[i].lower() == "ext":
            i += 1
            ext = binascii.unhexlify(args[i])
        else:
            key = args[i]
            i += 1
            registers[key] = _parse_int_expression(args[i])

        i += 1

    return rdcp_command.SetContext(thread_id, registers, ext, handler=print)


def _set_mem(args: [str]) -> Optional[rdcp_command.RDCPCommand]:
    """addr:int hexadecimal_string: str"""
    addr = _parse_int_expression(args[0])

    value = binascii.unhexlify("".join(args[1:]))

    return rdcp_command.SetMem(addr, value, handler=print)


def _stop_on(args: [str]) -> Optional[rdcp_command.RDCPCommand]:
    """<flag> [<flag> [...]] Enables automatic stop on events.

    flag:
      all          - All events
      fce          - First chance exceptions
      debugstr     - debugstr() invocations
      createthread - Thread creation
      stacktrace   - Stack traces
    """
    if args:
        events = 0
        for arg in args:
            arg = arg.lower()
            if arg == "all":
                events = 0xFFFFFFFF
                break

            if arg == "fce":
                events |= rdcp_command.StopOn.FIRST_CHANCE_EXCEPTION
            elif arg == "debugstr":
                events |= rdcp_command.StopOn.DEBUGSTR
            elif arg == "createthread":
                events |= rdcp_command.StopOn.CREATETHREAD
            elif arg == "stacktrace":
                events |= rdcp_command.StopOn.STACKTRACE
    else:
        events = 0xFFFFFFFF

    return rdcp_command.StopOn(events, handler=print)


def _reboot(args: [str]) -> Optional[rdcp_command.RDCPCommand]:
    """[<flag> [...]]

    Reboots the target machine.

    flags:
      wait - Wait for the debugger to attach on restart.
      stop - Stop at entry into the launch XBE.
      nodebug - Do not start XBDM when rebooting.
      warm - Do a warm reboot.
    """
    modes = {
        "wait": rdcp_command.Reboot.FLAG_WAIT,
        "warm": rdcp_command.Reboot.FLAG_WARM,
        "nodebug": rdcp_command.Reboot.FLAG_NO_DEBUG,
        "stop": rdcp_command.Reboot.FLAG_STOP,
    }

    mode = 0
    for arg in args:
        mode |= modes.get(arg.lower(), 0)
    return rdcp_command.Reboot(mode, handler=print)


def _walk_memory(_args) -> Optional[rdcp_command.RDCPCommand]:
    def _print_memory_walk(response: rdcp_command.WalkMem.Response):
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

    return rdcp_command.WalkMem(handler=_print_memory_walk)


def _xbe_info(args: [str]) -> Optional[rdcp_command.RDCPCommand]:
    if not args:
        return rdcp_command.XBEInfo(handler=print)

    on_disk_only = len(args) > 1
    rdcp_command.XBEInfo(args[0], on_disk_only, handler=print)


DISPATCH_TABLE = {
    "altaddr": _altaddr,
    "break": _break,
    "bye": lambda _: rdcp_command.Bye(handler=print),
    "continue": _continue,
    "debugoptions": _debug_options,
    "debugger": _debugger,
    "debugmode": lambda _: rdcp_command.DebugMode(handler=print),
    "dedicate": _dedicate,
    "rm": lambda args: rdcp_command.Delete(args[0], args[0][-1] == "/", handler=print),
    "ls": _dirlist,
    "dmversion": lambda _: rdcp_command.DMVersion(handler=print),
    "df": lambda args: rdcp_command.DriveFreeSpace(args[0][0], handler=print),
    "drivelist": lambda _: rdcp_command.DriveList(handler=print),
    "funccall": lambda args: rdcp_command.FuncCall(args[0], handler=print),
    "getcontext": _get_context,
    "getd3dstate": lambda _: rdcp_command.GetD3DState(handler=print),
    "getextcontext": lambda args: rdcp_command.GetExtContext(
        int(args[0], 0), handler=print
    ),
    # GetFile
    "getfileattr": lambda args: rdcp_command.GetFileAttributes(args[0], handler=print),
    "getgamma": lambda _: rdcp_command.GetGamma(handler=print),
    "getmem": _get_mem,
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
    "halt": _halt,
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
    "modules": _modules,
    "nostopon": _no_stop_on,
    # TODO: Convert channel to dedicated channel.
    # "notify": lambda _: rdcp_command.Notify(handler=print),
    "notifyat": _notifyat,
    # Dummy notifyat that will not spawn a listener even on a local address.
    "notifyatext": _notifyat,
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
    "setmem": _set_mem,
    # SetSystemTime
    "stop": lambda _: rdcp_command.Stop(handler=print),
    "stopon": _stop_on,
    "suspend": lambda args: rdcp_command.Suspend(int(args[0], 0), handler=print),
    "systemtime": lambda _: rdcp_command.SystemTime(handler=print),
    "threadinfo": lambda args: rdcp_command.ThreadInfo(int(args[0], 0), handler=print),
    "threads": lambda _: rdcp_command.Threads(handler=print),
    # UserList
    # VSSnap
    "memwalk": _walk_memory,
    "walkmem": _walk_memory,
    # WriteFile
    "xbeinfo": _xbe_info,
    "xtlinfo": lambda _: rdcp_command.XTLInfo(handler=print),
}
