"""Provides handlers for shell built-in commands."""
import enum
import textwrap
from typing import List
from typing import Optional

from . import commands
from xbdm.debugger import Debugger
from xbdm import rdcp_command
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
    if not shell._conn.reconnect(10):
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
    shell._conn.send_command(cmd)

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

    shell._debugger_context.debug_xbe(args[0], command_line=command_line)
    return Result.HANDLED


def _cmd_debugger_attach(shell, _args: [str]) -> Result:
    """

    Attach debugger to the current process."""
    if shell._debugger_context:
        print("Already in debug mode.")
    else:
        _attach_debugger(shell)
    return Result.HANDLED


def _cmd_debugger_restart(shell, _args: [str]) -> Result:
    """

    Restart the currently running XBE and breaks at the entrypoint."""
    if not shell._debugger_context:
        print("ERROR: /attach debugger first.")
        return Result.HANDLED

    shell._debugger_context.restart()
    return Result.HANDLED


def _cmd_debugger_set_active_thread(shell, args: [str]) -> Result:
    """ "<thread_id>

    Set the active thread.
    """
    if not shell._debugger_context:
        print("ERROR: /attach debugger first.")
        return Result.HANDLED

    thread_id = int(args[0], 0)
    shell._debugger_context.set_active_thread(thread_id)
    return Result.HANDLED


def _cmd_debugger_step_instruction(shell, _args: [str]) -> Result:
    """

    Step one instruction in the current thread."""
    if not shell._debugger_context:
        print("ERROR: /attach debugger first.")
        return Result.HANDLED

    shell._debugger_context.step_instruction()
    return Result.HANDLED


def _cmd_debugger_step_function(shell, _args: [str]) -> Result:
    """

    Step one function call in the current thread."""
    if not shell._debugger_context:
        print("ERROR: /attach debugger first.")
        return Result.HANDLED

    shell._debugger_context.step_function()
    return Result.HANDLED


def _cmd_debugger_get_thread_info(shell, _args: [str]) -> Result:
    """

    Print basic information about all threads."""
    if not shell._debugger_context:
        print("ERROR: /attach debugger first.")
        return Result.HANDLED

    shell._debugger_context.refresh_thread_info()

    thread_info: List[Thread] = sorted(
        shell._debugger_context.threads, key=lambda x: x.thread_id
    )
    for thread in thread_info:
        print(thread)

    return Result.HANDLED


def _cmd_debugger_getcontext(shell, _args: [str]) -> Result:
    """

    Print basic set of registers for the active thread context."""
    if not shell._debugger_context:
        print("ERROR: /attach debugger first.")
        return Result.HANDLED

    info: Optional[Thread.Context] = shell._debugger_context.get_thread_context()
    if not info:
        print("/switch to a valid thread and stop first.")
        return Result.HANDLED

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

    print(f"Registers for thread {shell._debugger_context.active_thread.thread_id}:")
    for reg in ordered_registers:
        value = info.registers.get(reg, None)
        if value is None:
            value = "???"
        else:
            value = "0x%08X" % value
        print("  %-11s: %s" % (reg, value))

    return Result.HANDLED


def _cmd_debugger_getfullcontext(shell, _args: [str]) -> Result:
    """

    Print full set of registers for the active thread context."""
    if not shell._debugger_context:
        print("ERROR: /attach debugger first.")
        return Result.HANDLED

    info: Thread.FullContext = shell._debugger_context.get_full_thread_context()
    print(info)

    return Result.HANDLED


def _cmd_debugger_halt_all(shell, _args: [str]) -> Result:
    """

    Halts all threads in the debugger."""
    if not shell._debugger_context:
        print("ERROR: /attach debugger first.")
        return Result.HANDLED

    if not shell._debugger_context.halt():
        print("Failed.")

    return Result.HANDLED


def _cmd_debugger_halt(shell, _args: [str]) -> Result:
    """

    Halts the active thread in the debugger."""
    if not shell._debugger_context:
        print("ERROR: /attach debugger first.")
        return Result.HANDLED

    thread: Optional[Thread] = shell._debugger_context.active_thread
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
    if not shell._debugger_context:
        print("ERROR: /attach debugger first.")
        return Result.HANDLED

    break_on_exceptions = True
    if args:
        break_on_exceptions = not _boolean_value(args[0])

    shell._debugger_context.continue_all(break_on_exceptions)

    return Result.HANDLED


def _cmd_debugger_continue(shell, args: [str]) -> Result:
    """[no_break_on_exceptions]

    Continues the active thread in the debugger.

    no_break_on_exceptions - if true, do not break on exceptions when continuing.
    """
    if not shell._debugger_context:
        print("ERROR: /attach debugger first.")
        return Result.HANDLED

    thread: Optional[Thread] = shell._debugger_context.active_thread
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
    if not shell._debugger_context:
        print("ERROR: /attach debugger first.")
        return Result.HANDLED

    thread: Optional[Thread] = shell._debugger_context.active_thread
    if not thread:
        print("/switch to a valid thread first.")
        return Result.HANDLED

    if not thread.suspend():
        print("Failed.")

    return Result.HANDLED


def _cmd_debugger_resume(shell, _args: [str]) -> Result:
    """

    Resumes (or reduces the suspend count on) the active thread."""
    if not shell._debugger_context:
        print("ERROR: /attach debugger first.")
        return Result.HANDLED

    thread: Optional[Thread] = shell._debugger_context.active_thread
    if not thread:
        print("/switch to a valid thread first.")
        return Result.HANDLED

    if not thread.resume():
        print("Failed.")

    return Result.HANDLED


def _attach_debugger(shell):
    if not shell._debugger_context:
        shell._debugger_context = Debugger(shell._conn)
        shell._debugger_context.attach()


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
    "/stepfun": _cmd_debugger_step_function,
    "/context": _cmd_debugger_getcontext,
    "/fullcontext": _cmd_debugger_getfullcontext,
    "/haltall": _cmd_debugger_halt_all,
    "/halt": _cmd_debugger_halt,
    "/continueall": _cmd_debugger_continue_all,
    "/continue": _cmd_debugger_continue,
    "/suspend": _cmd_debugger_suspend,
    "/resume": _cmd_debugger_resume,
}
