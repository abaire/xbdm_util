"""Provides handlers for shell built-in commands."""
import binascii
import enum
import textwrap
from typing import List
from typing import Optional

from . import commands
from xbdm import rdcp_command
from xbdm.debugger import Debugger
from xbdm.debugger import Thread


class Result(enum.Enum):
    NOT_HANDLED = 0
    HANDLED = 1
    EXIT_REQUESTED = 2


def _boolean_value(argument: str) -> bool:
    arg = argument.lower()
    return arg == "true" or arg == "1" or arg == "t" or arg == "yes" or arg == "y"


def _cmd_exit(_shell, _args: [str]) -> Result:
    """

    Terminate the connection and exit."""
    return Result.EXIT_REQUESTED


def _cmd_help(_shell, args: [str]) -> Result:
    """[command]

    With no argument, prints all commands.
    With an argument, prints detailed help about that command.
    """
    if args:
        cmd = args[0].lower()
        handler = commands.DISPATCH_TABLE.get(cmd)
        if not handler:
            handler = DISPATCH_TABLE.get(cmd)

        if not handler:
            print("Invalid command")
        else:
            print(f"{cmd} {handler.__doc__}")
        return Result.HANDLED

    cmds = sorted([k for k, v in commands.DISPATCH_TABLE.items() if v])
    print("XBDM commands:")
    print(textwrap.fill(", ".join(cmds), 80))

    print("\nShell commands:")
    print(textwrap.fill(", ".join(sorted(DISPATCH_TABLE.keys()))))

    return Result.HANDLED


def _cmd_reconnect(shell, _args: [str]) -> Result:
    """

    Attempt to disconnect and reconnect to XBDM."""
    if not shell._bridge.reconnect(10):
        print("Failed to reconnect.")
    else:
        print("Connected")
    return Result.HANDLED


def _cmd_send_raw(shell, args: [str]) -> Result:
    """[...]

    Sends whatever is present after the command as a raw \\r\\n terminated string.
    (WARNING: whitespace will be collapsed: 'a  string' => 'a string\\r\\n')
    """
    body = None
    if len(args) > 1:
        body = bytes(" ".join(args[1:]), "utf-8")
    cmd = rdcp_command.RDCPCommand(args[0], body)
    shell._bridge.send_command(cmd)

    return Result.HANDLED


def _cmd_debugger_launch(shell, args: [str]) -> Result:
    """<path_to_xbe> [commandline_arg [...]]

    Launch the given path in the debugger, passing any remaining parameters as launch args.
    """

    _attach_debugger(shell)

    xbe = args[0]
    if len(args) > 1:
        command_line = " ".join(args[1:])
    else:
        command_line = None

    debugger: Debugger = shell._debugger
    debugger.debug_xbe(args[0], command_line=command_line)
    return Result.HANDLED


def _cmd_debugger_attach(shell, _args: [str]) -> Result:
    """

    Attach debugger to the current process."""
    if shell._debugger:
        print("Already in debug mode.")
    else:
        _attach_debugger(shell)
    return Result.HANDLED


def _cmd_debugger_restart(shell, _args: [str]) -> Result:
    """

    Restart the currently running XBE and breaks at the entrypoint."""
    if not shell._debugger:
        print("ERROR: /attach debugger first.")
        return Result.HANDLED

    debugger: Debugger = shell._debugger
    debugger.restart()
    return Result.HANDLED


def _cmd_debugger_set_active_thread(shell, args: [str]) -> Result:
    """ "<thread_id>

    Set the active thread.
    """
    if not shell._debugger:
        print("ERROR: /attach debugger first.")
        return Result.HANDLED

    thread_id = int(args[0], 0)
    debugger: Debugger = shell._debugger
    debugger.set_active_thread(thread_id)
    return Result.HANDLED


def _cmd_debugger_step_instruction(shell, _args: [str]) -> Result:
    """

    Step one instruction in the current thread."""
    if not shell._debugger:
        print("ERROR: /attach debugger first.")
        return Result.HANDLED

    debugger: Debugger = shell._debugger
    debugger.step_instruction()
    return Result.HANDLED


def _cmd_debugger_step_function(shell, _args: [str]) -> Result:
    """

    Step one function call in the current thread."""
    if not shell._debugger:
        print("ERROR: /attach debugger first.")
        return Result.HANDLED

    debugger: Debugger = shell._debugger
    debugger.step_function()
    return Result.HANDLED


def _cmd_debugger_get_thread_info(shell, _args: [str]) -> Result:
    """

    Print basic information about all threads."""
    if not shell._debugger:
        print("ERROR: /attach debugger first.")
        return Result.HANDLED

    shell._debugger.refresh_thread_info()

    thread_info: List[Thread] = sorted(
        shell._debugger.threads, key=lambda x: x.thread_id
    )
    for thread in thread_info:
        print(thread)

    return Result.HANDLED


def _print_thread_context(thread_id: int, info: Optional[Thread.Context]):
    if not info:
        print(f"Register information not available for thread {thread_id}")
        return

    ordered_registers = [
        "Eip",
        "Ebp",
        "Esp",
        "EFlags",
        "Eax",
        "Ebx",
        "Ecx",
        "Edx",
        "Edi",
        "Esi",
        "Cr0NpxState",
    ]

    print(f"Registers for thread {thread_id}:")
    for reg in ordered_registers:
        value = info.registers.get(reg, None)
        if value is None:
            value = "???"
        else:
            value = "0x%08X" % value
        print("  %-11s: %s" % (reg, value))


def _print_thread_ext_context(thread_id: int, info: Optional[Thread.FullContext]):
    if not info or not info.ext_register_data:
        print(f"Extended register information not available for thread {thread_id}")
        return

    _print_thread_context(thread_id, info)

    context_keys = [
        "control",
        "status",
        "tag",
        "error_offset",
        "error_selector",
        "data_offset",
        "data_selector",
        "ST0",
        "ST1",
        "ST2",
        "ST3",
        "ST4",
        "ST5",
        "ST6",
        "ST7",
    ]

    print(f"Extended context:")
    for key in context_keys:
        value = info.ext_register_data.get(key, None)
        if value is None:
            value = "???"
        else:
            value = "0x%08X" % value
        print("  %-15s: %s" % (key, value))


# eax            0x2                 2
# ecx            0x8004ab40          -2147177664
# edx            0xb0a9              45225
# ebx            0x8004ac8c          -2147177332
# esp            0x8004ea70          0x8004ea70
# ebp            0x8004acdc          0x8004acdc
# esi            0x8004ab40          -2147177664
# edi            0xd0027ab8          -805143880
# eip            0x80024a97          0x80024a97
# eflags         0x246               [ IOPL=0 IF ZF PF ]
# cs             0x8                 8
# ss             0x10                16
# ds             0x10                16
# es             0x10                16
# fs             0x20                32
# gs             0x0                 0
# fs_base        0x8004ac8c          -2147177332
# gs_base        0x0                 0
# k_gs_base      0x0                 0
# cr0            0x8001003b          [ PG WP NE ET TS MP PE ]
# cr2            0x0                 0
# cr3            0xf000              [ PDBR=0 PCID=0 ]
# cr4            0x610               [ PSE OSFXSR OSXMMEXCPT ]
# cr8            0x0                 0
# efer           0x0                 [ ]
# xmm0           {v4_float = {0x0, 0x0, 0x0, 0x0}, v2_double = {0x0, 0x0}, v16_int8 = {0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}, v8_int16 = {0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}, v4_int32 = {0x0, 0x0, 0x0, 0x0}, v2_int64 = {0x0, 0x0}, uint128 = 0x0}
# xmm1           {v4_float = {0x1, 0x140, 0xf0, 0x0}, v2_double = {0x800001fc0000000, 0x0}, v16_int8 = {0x0, 0x0, 0x80, 0x3f, 0x0, 0x0, 0xa0, 0x43, 0x0, 0x0, 0x70, 0x43, 0x0, 0x0, 0x0, 0x0}, v8_int16 = {0x0, 0x3f80, 0x0, 0x43a0, 0x0, 0x4370, 0x0, 0x0}, v4_int32 = {0x3f800000, 0x43a00000, 0x43700000, 0x0}, v2_int64 = {0x43a000003f800000, 0x43700000}, uint128 = 0x4370000043a000003f800000}
# xmm2           {v4_float = {0x0, 0x140, 0x0, 0x0}, v2_double = {0x800000000000000, 0x0}, v16_int8 = {0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0xa0, 0x43, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}, v8_int16 = {0x0, 0x0, 0x0, 0x43a0, 0x0, 0x0, 0x0, 0x0}, v4_int32 = {0x0, 0x43a00000, 0x0, 0x0}, v2_int64 = {0x43a0000000000000, 0x0}, uint128 = 0x43a0000000000000}
# xmm3           {v4_float = {0x0, 0x0, 0xffffff10, 0x0}, v2_double = {0x0, 0x0}, v16_int8 = {0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x70, 0xc3, 0x0, 0x0, 0x0, 0x0}, v8_int16 = {0x0, 0x0, 0x0, 0x0, 0x0, 0xc370, 0x0, 0x0}, v4_int32 = {0x0, 0x0, 0xc3700000, 0x0}, v2_int64 = {0x0, 0xc3700000}, uint128 = 0xc37000000000000000000000}
# xmm4           {v4_float = {0x0, 0x0, 0x0, 0x0}, v2_double = {0x0, 0x0}, v16_int8 = {0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}, v8_int16 = {0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}, v4_int32 = {0x0, 0x0, 0x0, 0x0}, v2_int64 = {0x0, 0x0}, uint128 = 0x0}
# xmm5           {v4_float = {0x1, 0x140, 0xf0, 0x0}, v2_double = {0x800001fc0000000, 0x0}, v16_int8 = {0x0, 0x0, 0x80, 0x3f, 0x0, 0x0, 0xa0, 0x43, 0x0, 0x0, 0x70, 0x43, 0x0, 0x0, 0x0, 0x0}, v8_int16 = {0x0, 0x3f80, 0x0, 0x43a0, 0x0, 0x4370, 0x0, 0x0}, v4_int32 = {0x3f800000, 0x43a00000, 0x43700000, 0x0}, v2_int64 = {0x43a000003f800000, 0x43700000}, uint128 = 0x4370000043a000003f800000}
# xmm6           {v4_float = {0x0, 0x0, 0x0, 0x0}, v2_double = {0x0, 0x0}, v16_int8 = {0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}, v8_int16 = {0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}, v4_int32 = {0x0, 0x0, 0x0, 0x0}, v2_int64 = {0x0, 0x0}, uint128 = 0x0}
# xmm7           {v4_float = {0x0, 0x0, 0x0, 0x0}, v2_double = {0x0, 0x0}, v16_int8 = {0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0xa0, 0x1f, 0x0, 0x0}, v8_int16 = {0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1fa0, 0x0}, v4_int32 = {0x0, 0x0, 0x0, 0x1fa0}, v2_int64 = {0x0, 0x1fa000000000}, uint128 = 0x1fa0000000000000000000000000}
# mxcsr          0x1fa0              [ PE IM DM ZM OM UM PM ]


def _cmd_debugger_get_all_thread_info(shell, _args: [str]) -> Result:
    """

    Prints all possible information about the active thread context."""
    if not shell._debugger:
        print("ERROR: /attach debugger first.")
        return Result.HANDLED

    thread: Thread = shell._debugger.active_thread
    if not thread:
        print("/switch to a valid thread and stop first.")
        return Result.HANDLED

    thread.get_info()
    context = shell._debugger.get_full_thread_context()

    if thread.suspend_count:
        print(f"Suspended: count: {thread.suspend_count}")
    print(f"Priority: {thread.priority}")

    if thread.thread_local_storage_addr:
        print("Thread local storage base: 0x%08X" % thread.thread_local_storage_addr)

    print("Start address: 0x%08X" % thread.start_addr)
    print("Base address: 0x%08X" % thread.base_addr)
    print("Limit: 0x%08X" % thread.limit)
    print("Create timestamp: 0x%08X" % thread.create_time)
    _print_thread_ext_context(shell._debugger.active_thread.thread_id, context)


def _cmd_debugger_getcontext(shell, _args: [str]) -> Result:
    """

    Print basic set of registers for the active thread context."""
    if not shell._debugger:
        print("ERROR: /attach debugger first.")
        return Result.HANDLED

    info: Optional[Thread.Context] = shell._debugger.get_thread_context()
    if not info:
        print("/switch to a valid thread and stop first.")
        return Result.HANDLED

    _print_thread_context(shell._debugger.active_thread.thread_id, info)
    return Result.HANDLED


def _cmd_debugger_getfullcontext(shell, _args: [str]) -> Result:
    """

    Print full set of registers for the active thread context."""
    if not shell._debugger:
        print("ERROR: /attach debugger first.")
        return Result.HANDLED

    info: Thread.FullContext = shell._debugger.get_full_thread_context()
    print(info)

    return Result.HANDLED


def _cmd_debugger_halt_all(shell, _args: [str]) -> Result:
    """

    Halts all threads in the debugger."""
    if not shell._debugger:
        print("ERROR: /attach debugger first.")
        return Result.HANDLED

    if not shell._debugger.halt():
        print("Failed.")

    return Result.HANDLED


def _cmd_debugger_halt(shell, _args: [str]) -> Result:
    """

    Halts the active thread in the debugger."""
    if not shell._debugger:
        print("ERROR: /attach debugger first.")
        return Result.HANDLED

    thread: Optional[Thread] = shell._debugger.active_thread
    if not thread:
        print("/switch to a valid thread first.")
        return Result.HANDLED

    if not thread.halt():
        print("Failed.")

    return Result.HANDLED


def _cmd_debugger_continue_all(shell, args: [str]) -> Result:
    """[no_break_on_exceptions]

    Continues all halted threads in the debugger.

    no_break_on_exceptions - if true, do not break on exceptions when continuing.
    """
    if not shell._debugger:
        print("ERROR: /attach debugger first.")
        return Result.HANDLED

    break_on_exceptions = True
    if args:
        break_on_exceptions = not _boolean_value(args[0])

    shell._debugger.continue_all(break_on_exceptions)

    return Result.HANDLED


def _cmd_debugger_continue(shell, args: [str]) -> Result:
    """[no_break_on_exceptions]

    Continues the active thread in the debugger.

    no_break_on_exceptions - if true, do not break on exceptions when continuing.
    """
    if not shell._debugger:
        print("ERROR: /attach debugger first.")
        return Result.HANDLED

    thread: Optional[Thread] = shell._debugger.active_thread
    if not thread:
        print("/switch to a valid thread first.")
        return Result.HANDLED

    break_on_exceptions = True
    if args:
        break_on_exceptions = not _boolean_value(args[0])

    if not thread.continue_once(break_on_exceptions=break_on_exceptions):
        print("Failed.")

    return Result.HANDLED


def _cmd_debugger_suspend(shell, _args: [str]) -> Result:
    """

    Suspends (or raises the suspend count on) the active thread."""
    if not shell._debugger:
        print("ERROR: /attach debugger first.")
        return Result.HANDLED

    thread: Optional[Thread] = shell._debugger.active_thread
    if not thread:
        print("/switch to a valid thread first.")
        return Result.HANDLED

    if not thread.suspend():
        print("Failed.")

    return Result.HANDLED


def _cmd_debugger_resume(shell, _args: [str]) -> Result:
    """

    Resumes (or reduces the suspend count on) the active thread."""
    if not shell._debugger:
        print("ERROR: /attach debugger first.")
        return Result.HANDLED

    thread: Optional[Thread] = shell._debugger.active_thread
    if not thread:
        print("/switch to a valid thread first.")
        return Result.HANDLED

    if not thread.resume():
        print("Failed.")

    return Result.HANDLED


def _attach_debugger(shell):
    if not shell._debugger:
        shell.attach_debugger()


DISPATCH_TABLE = {
    "exit": _cmd_exit,
    "quit": _cmd_exit,
    "q": _cmd_exit,
    "?": _cmd_help,
    "help": _cmd_help,
    "h": _cmd_help,
    "reconnect": _cmd_reconnect,
    "raw": _cmd_send_raw,
    "/launch": _cmd_debugger_launch,
    "/attach": _cmd_debugger_attach,
    "/restart": _cmd_debugger_restart,
    "/switch": _cmd_debugger_set_active_thread,
    "/threads": _cmd_debugger_get_thread_info,
    "/stepi": _cmd_debugger_step_instruction,
    "/stepf": _cmd_debugger_step_function,
    "/stepfun": _cmd_debugger_step_function,
    "/info": _cmd_debugger_get_all_thread_info,
    "/context": _cmd_debugger_getcontext,
    "/fullcontext": _cmd_debugger_getfullcontext,
    "/haltall": _cmd_debugger_halt_all,
    "/halt": _cmd_debugger_halt,
    "/continueall": _cmd_debugger_continue_all,
    "/continue": _cmd_debugger_continue,
    "/suspend": _cmd_debugger_suspend,
    "/resume": _cmd_debugger_resume,
}
