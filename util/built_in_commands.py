"""Provides handlers for shell built-in commands."""
import enum
import socket
import textwrap
from typing import Callable
from typing import List
from typing import Optional
from typing import Tuple

import gdb
from . import commands
from net import ip_transport
from xbdm import rdcp_command
from xbdm.debugger import Debugger
from xbdm.debugger import Thread
from xbdm import xbdm_bridge


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


def _cmd_start_gdb_bridge(shell, args: [str]) -> Result:
    """[ip:port]

    Starts a GDB bridge, allowing GDB to communicate with the XBDM target.

    ip:port - The ip and port to listen for GDB at. Both components are optional, with
              default behavior being to bind to all local IPs on an arbitrary port.
    """
    listen_ip: str = ""
    listen_port: int = 0

    if args:
        components = args[0].split(":")
        if len(components) > 2:
            print("Address must be of the form 'ip:port'.")
            return Result.HANDLED

        components = list(components)
        if len(components) == 2:
            listen_port = int(components[1])
        listen_ip = components[0]

    def construct_transport(
        bridge: xbdm_bridge.XBDMBridge,
        remote: socket.socket,
        remote_addr: Tuple[str, int],
    ) -> Optional[ip_transport.IPTransport]:

        ret = gdb.GDBTransport(bridge, f"GDB@{remote_addr}", shell._debugger)
        ret.set_connection(remote, remote_addr)
        return ret

    bridge: xbdm_bridge.XBDMBridge = shell._bridge
    bridge.destroy_remote_listener()
    bridge.create_remote_listener((listen_ip, listen_port), construct_transport)
    print(f"Listening for GDB connections at {bridge.remote_listen_addr}")

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


def _cmd_debugger_launch_wait(shell, args: [str]) -> Result:
    """<path_to_xbe> [commandline_arg [...]]

    Launch the given path in the debugger, passing any remaining parameters as launch args.
    A breakpoint will be set at the XBE entrypoint, but execution will be held until a
    `go` command is sent.
    """

    _attach_debugger(shell)

    xbe = args[0]
    if len(args) > 1:
        command_line = " ".join(args[1:])
    else:
        command_line = None

    debugger: Debugger = shell._debugger
    debugger.debug_xbe(args[0], command_line=command_line, wait_before_start=True)
    return Result.HANDLED


def _cmd_debugger_launch_persistent(shell, args: [str]) -> Result:
    """<path_to_xbe> [commandline_arg [...]]

    Launch the given path in the debugger, passing any remaining parameters as launch
    args and have any future reboots run this same XBE until /clear is invoked.
    """

    _attach_debugger(shell)

    xbe = args[0]
    if len(args) > 1:
        command_line = " ".join(args[1:])
    else:
        command_line = None

    debugger: Debugger = shell._debugger
    debugger.debug_xbe(args[0], command_line=command_line, persist=True)
    return Result.HANDLED


def _cmd_debugger_clear_launch_target(shell, _args: [str]) -> Result:
    """

    Clears any previously set /launchpersist target.
    """
    if not shell._debugger:
        print("ERROR: /attach debugger first.")
        return Result.HANDLED

    debugger: Debugger = shell._debugger
    debugger.clear_debug_xbe()
    return Result.HANDLED


def _cmd_debugger_attach(shell, _args: [str]) -> Result:
    """

    Attach debugger to the current process."""
    if shell._debugger:
        print("Already in debug mode.")
    else:
        _attach_debugger(shell)
    return Result.HANDLED


def _cmd_debugger_detach(shell, _args: [str]) -> Result:
    """

    Detach from the target process (note that this does not clear breakpoints/etc...)."""
    if not shell._debugger:
        print("Not in debug mode.")
    else:
        shell._debugger = None
        cmd = rdcp_command.Debugger(False)
        shell._bridge.send_command(cmd)
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
    if not info or not info.ext_registers:
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
        value = info.ext_registers.get(key, None)
        if value is None:
            value = "???"
        else:
            value = "0x%08X" % value
        print("  %-15s: %s" % (key, value))


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
    "gdb": _cmd_start_gdb_bridge,
    "/launch": _cmd_debugger_launch,
    "/launchwait": _cmd_debugger_launch_wait,
    "/launchpersist": _cmd_debugger_launch_persistent,
    "/clearpersist": _cmd_debugger_clear_launch_target,
    "/attach": _cmd_debugger_attach,
    "/detach": _cmd_debugger_detach,
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
