"""Provides higher level functions for step-debugging functionality."""
from __future__ import annotations

import binascii
import collections
import logging
import os
import re
import threading

import struct
import time

from xbdm import rdcp_command
from xbdm.xbdm_bridge import XBDMBridge
from xbdm.xbdm_notification_server import XBDMNotificationServer

from typing import Callable
from typing import Dict
from typing import Iterable
from typing import Optional

logger = logging.getLogger(__name__)


def _parse_ext_registers(info: bytes) -> Dict[str, int]:
    (
        control,
        status,
        tag,
        error_offset,
        error_selector,
        data_offset,
        data_selector,
    ) = struct.unpack_from("IIIIIII", info, 0)
    offset = 7 * 4
    registers = info[offset : offset + 80]

    offset += 80
    cr0NpxState = struct.unpack_from("I", info, offset)[0]

    ext_info = {
        "fctrl": control,
        "fstat": status,
        "ftag": tag,
        "fiseg": error_offset,
        "fioff": error_selector,
        "foseg": data_offset,
        "fooff": data_selector,
        "fop": cr0NpxState,
    }

    # Unpack ST0 - ST7
    for i in range(8):
        low_dword, high_word = struct.unpack_from("IH", registers, i * 10)
        ext_info["ST%d" % i] = low_dword + (high_word << 8)

    return ext_info


class _XBDMClient:
    """Provides functionality for communicating with an XBDMConnection."""

    def __init__(self, connection: XBDMBridge):
        self._connection = connection

    def _call(
        self, cmd: rdcp_command.ProcessedCommand
    ) -> rdcp_command.ProcessedResponseCatcher:
        """Sends a command to the underlying connection and waits for the response."""
        response = self._call_async(cmd)
        self._connection.await_empty_queue()
        return response

    def _call_async(
        self, cmd: rdcp_command.ProcessedCommand
    ) -> rdcp_command.ProcessedResponseCatcher:
        """Sends a command to the underlying connection and immediately returns a handler that will eventually receive the result."""
        response = rdcp_command.ProcessedResponseCatcher()
        cmd.set_handler(response)
        self._connection.send_command(cmd)
        return response


class Thread(_XBDMClient):
    """Encapsulates information about a thread."""

    class Context:
        """Contains registers for a Thread."""

        def __init__(self, registers: Dict[str, Optional[int]]):
            self.registers = registers

    class FullContext(Context):
        """Contains registers and extended registers for a Thread."""

        def __init__(
            self,
            registers: Dict[str, Optional[int]],
            ext_registers: Optional[bytes] = None,
        ):
            super().__init__(registers)

            self.basic_registers = dict(self.registers)
            self.ext_registers = None
            if ext_registers:
                self.ext_registers = _parse_ext_registers(ext_registers)
                self.registers.update(self.ext_registers)

    _TRAP_FLAG = 0x100

    def __init__(self, thread_id: int, connection: XBDMBridge):
        super().__init__(connection)
        self.thread_id = thread_id

        self.suspend_count: Optional[int] = None
        self.priority: Optional[int] = None
        self.thread_local_storage_addr: Optional[int] = None
        self.start_addr: Optional[int] = None
        self.base_addr: Optional[int] = None
        self.limit: Optional[int] = None
        self.create_time: Optional[int] = None

        self.get_info()

        self.last_known_address: Optional[int] = None
        self.last_stop_reason: Optional[rdcp_command.IsStopped.StopReason]

    def __str__(self) -> str:
        lines = [
            f"Thread: {self.thread_id}",
            "  Priority: %d %s"
            % (
                self.priority,
                f"[Suspended {self.suspend_count}]" if self.suspend_count else "",
            ),
            "  Base : 0x%08X" % (self.base_addr or 0),
            "  Start: 0x%08X" % (self.start_addr or 0),
            "  Thread Local Base: 0x%08X" % (self.thread_local_storage_addr or 0),
            "  Limit: 0x%08X" % (self.limit or 0),
            "  CreatedAt: 0x%08X" % (self.create_time or -1),
        ]
        return "\n".join(lines)

    @property
    def last_stop_reason_signal(self) -> int:
        """Returns a signal number representing the reason this thread was last stopped."""
        if not self.last_stop_reason:
            return 0
        return self.last_stop_reason.signal

    def get_info(self):
        response = self._call(rdcp_command.ThreadInfo(self.thread_id))
        assert response.ok

        self.suspend_count = response.suspend
        self.priority = response.priority
        self.thread_local_storage_addr = response.tlsbase
        self.start_addr = response.start
        self.base_addr = response.base
        self.limit = response.limit
        # TODO: Convert to a unix timestmap for ease of display.
        self.create_time = response.create

    def get_context(self) -> Optional[Context]:
        registers = self._get_context()
        if not registers:
            return None
        return self.Context(registers)

    def get_full_context(self) -> Optional[FullContext]:
        basic_registers = self._get_context()
        if not basic_registers:
            return None

        ext_registers = None
        response = self._call(rdcp_command.GetExtContext(self.thread_id))
        if response.ok:
            ext_registers = response.data

        return self.FullContext(basic_registers, ext_registers)

    def _get_context(self) -> Optional[Dict[str, Optional[int]]]:
        response = self._call(
            rdcp_command.GetContext(
                self.thread_id,
                enable_float=True,
                enable_control=True,
                enable_integer=True,
            )
        )
        if not response.ok:
            return None
        return response.registers

    def set_step_instruction_mode(self, enabled: bool) -> bool:
        context = self.get_context()
        if not context:
            return False

        old_flags = context.registers["EFlags"]
        if enabled:
            new_flags = old_flags | self._TRAP_FLAG
        else:
            new_flags = old_flags & self._TRAP_FLAG
        if new_flags == old_flags:
            return True

        response = self._call(
            rdcp_command.SetContext(self.thread_id, {"EFlags": new_flags})
        )
        return response.ok

    def prepare_step_function(self) -> bool:
        if not self.halt():
            return False
        if not self._set_step_function():
            return False
        return self.continue_once()

    def _set_step_function(self) -> bool:
        response = self._call(rdcp_command.FuncCall(self.thread_id))
        return response.ok

    def halt(self) -> bool:
        """Sends a 'halt' command."""
        response = self._call(rdcp_command.Halt(self.thread_id))
        if not response.ok:
            return False
        self.get_info()
        return True

    def continue_once(self, break_on_exceptions: bool = True) -> bool:
        """Sends a 'continue' command."""
        response = self._call(
            rdcp_command.Continue(self.thread_id, exception=break_on_exceptions)
        )
        if not response.ok:
            return False
        self.get_info()
        return True

    def suspend(self) -> bool:
        """Sends a 'suspend' command."""
        response = self._call(rdcp_command.Suspend(self.thread_id))
        if not response.ok:
            return False
        self.get_info()
        return True

    def resume(self) -> bool:
        """Sends a 'resume' command."""
        response = self._call(rdcp_command.Resume(self.thread_id))
        if not response.ok:
            return False
        self.get_info()
        return True

    # def unsuspend(self):
    #     """Sends continue commands until suspend count is 0."""
    #     self.get_info()
    #     while self.suspend_count > 0:
    #         self._connection.send_command(rdcp_command.Continue(self.thread_id))

    def fetch_stop_reason(self) -> bool:
        response = self._call(rdcp_command.IsStopped(self.thread_id))
        if not response:
            return False

        if not response.stopped:
            self.last_stop_reason = None
        else:
            self.last_stop_reason = response.reason
        return True


def _match_hex(key: str) -> str:
    """Returns a string containing a regex matching key=<hex_or_integer_string>"""
    return f"{key}=((?:0x)?[0-9a-fA-F]+)"


class Module:
    def __init__(
        self,
        name: str,
        base_address: int,
        size: int,
        checksum: int,
        timestamp: int,
        attributes: Optional[Iterable[str]] = None,
    ):
        self.name = name
        self.base_address = base_address
        self.size = size
        self.checksum = checksum
        self.timestamp = timestamp
        self.attributes = attributes

    def __str__(self):
        if self.attributes:
            attribute_str = " " + " ".join(sorted(self.attributes))
        else:
            attribute_str = ""

        return "%s: %s Mem: 0x%X - 0x%X (%d) Check: 0x%08X%s" % (
            self.__class__.__name__,
            self.name,
            self.base_address,
            self.base_address + self.size,
            self.size,
            self.checksum,
            attribute_str,
        )

    # 'name="XShell_new.exe" base=0x00010bc0 size=0x001c5880 check=0x00000000 timestamp=0x00000000 tls xbe'
    _RE = re.compile(
        r"name=\"([^\"]+)\"\s+"
        + r"\s+".join([_match_hex(x) for x in ["base", "size", "check", "timestamp"]])
        + r"\s*(.*)"
    )

    @classmethod
    def parse(cls, message: str) -> Optional[Module]:
        match = cls._RE.match(message)
        if not match:
            return None

        attributes = None
        if match.group(6):
            attributes = match.group(6).split(" ")

        return cls(
            name=match.group(1),
            base_address=int(match.group(2), 0),
            size=int(match.group(3), 0),
            checksum=int(match.group(4), 0),
            timestamp=int(match.group(5), 0),
            attributes=attributes,
        )


class Section:
    def __init__(
        self, name: str, base_address: int, size: int, index: int, flags: int = 0
    ):
        self.name = name
        self.base_address = base_address
        self.size = size
        self.index = index
        self.flags = flags

    def __str__(self):
        return "%s: %s @%d Flags: 0x08%X Mem: 0x%X - 0x%X (%d)" % (
            self.__class__.__name__,
            self.name,
            self.size,
            self.flags,
            self.base_address,
            self.base_address + self.size,
            self.size,
        )

    # 'name="XONLINE" base=0x00011000 size=0x00054eec index=0 flags=1'
    _RE = re.compile(
        r"name=\"([^\"]+)\"\s+"
        + r"\s+".join([_match_hex(x) for x in ["base", "size", "index", "flags"]])
    )

    @classmethod
    def parse(cls, message: str) -> Optional[Section]:
        match = cls._RE.match(message)
        if not match:
            return None

        return cls(
            name=match.group(1),
            base_address=int(match.group(2), 0),
            size=int(match.group(3), 0),
            index=int(match.group(4), 0),
            flags=int(match.group(5), 0),
        )


class NotificationHandler:
    """Handles asynchronous notifications from XBDM."""

    def debugstr(self, _thread_id: int, _text: str):
        pass

    def vx(self, _message: str):
        pass

    def module_load(self, _mod: Module):
        pass

    def section_load(self, _sect: Section):
        pass

    def create_thread(self, _thread_id: int, _start_address: int):
        pass

    def terminate_thread(self, _thread_id: int):
        pass

    def execution_state_change(self, _new_state: str):
        pass

    def breakpoint(self, _thread_id: int, _address: int, _reason: str):
        pass

    def data_breakpoint(
        self,
        _thread_id: int,
        _access: str,
        _access_address: int,
        _address: int,
        _reason: str,
    ):
        pass

    def step(self, _thread_id: int, _address: int):
        pass


class DefaultNotificationHandler(NotificationHandler):
    """Default notification handler that just prints to the console."""

    def debugstr(self, thread_id: int, text: str):
        print("DBG[%03d]> %s" % (thread_id, text))

    def vx(self, message: str):
        print(f"vx: {message}")

    def module_load(self, mod: Module):
        print(f"Loaded module: {mod}")

    def section_load(self, sect: Section):
        print(f"Loaded section: {sect}")

    def create_thread(self, thread_id: int, start_address: int):
        print(f"Created thread: {thread_id} start_addr: 0x%08X" % start_address)

    def terminate_thread(self, thread_id: int):
        print(f"Terminate thread: {thread_id}")

    def execution_state_change(self, new_state: str):
        print(f"EXECUTION STATE CHANGE: {new_state}")

    def breakpoint(self, thread_id: int, address: int, reason: str):
        print("BREAK: %d @ 0x%X %s" % (thread_id, address, reason))

    def data_breakpoint(
        self,
        thread_id: int,
        access: str,
        access_address: int,
        address: int,
        reason: str,
    ):
        print(
            "DATA BREAK: %d: %s@0x%08X @ 0x%X %s"
            % (thread_id, access, access_address, address, reason)
        )

    def step(self, thread_id: int, address: int):
        print("STEP: %d @ 0x%X" % (thread_id, address))


class RedirectingNotificationHandler(NotificationHandler):
    """Redirects notifications to callbacks passed in init."""

    def __init__(
        self,
        on_debugstr=None,
        on_vx=None,
        on_module_load=None,
        on_section_load=None,
        on_create_thread=None,
        on_terminate_thread=None,
        on_execution_state_change=None,
        on_breakpoint=None,
        on_data_breakpoint=None,
        on_step=None,
    ):
        super().__init__()

        def default_handler(*args):
            pass

        self.on_debugstr = on_debugstr if on_debugstr else default_handler
        self.on_vx = on_vx if on_vx else default_handler
        self.on_module_load = on_module_load if on_module_load else default_handler
        self.on_section_load = on_section_load if on_section_load else default_handler
        self.on_create_thread = (
            on_create_thread if on_create_thread else default_handler
        )
        self.on_terminate_thread = (
            on_terminate_thread if on_terminate_thread else default_handler
        )
        self.on_execution_state_change = (
            on_execution_state_change if on_execution_state_change else default_handler
        )
        self.on_breakpoint = on_breakpoint if on_breakpoint else default_handler
        self.on_data_breakpoint = (
            on_data_breakpoint if on_data_breakpoint else default_handler
        )
        self.on_step = on_step if on_step else default_handler

    def debugstr(self, thread_id: int, text: str):
        self.on_debugstr(thread_id, text)

    def vx(self, message: str):
        self.on_vx(message)

    def module_load(self, mod: Module):
        self.on_module_load(mod)

    def section_load(self, sect: Section):
        self.on_section_load(sect)

    def create_thread(self, thread_id: int, start_address: int):
        self.on_create_thread(thread_id, start_address)

    def terminate_thread(self, thread_id: int):
        self.on_terminate_thread(thread_id)

    def execution_state_change(self, new_state: str):
        self.on_execution_state_change(new_state)

    def breakpoint(self, thread_id: int, address: int, reason: str):
        self.on_breakpoint(thread_id, address, reason)

    def data_breakpoint(
        self,
        thread_id: int,
        access: str,
        access_address: int,
        address: int,
        reason: str,
    ):
        self.on_data_breakpoint(thread_id, access, access_address, address, reason)

    def step(self, thread_id: int, address: int):
        self.on_step(thread_id, address)


class Debugger(_XBDMClient):
    """Provides high level debugger functionality."""

    def __init__(
        self,
        connection: XBDMBridge,
        notification_handler: Optional[NotificationHandler] = None,
    ):
        super().__init__(connection)
        self._debug_port = None

        self._notification_dispatch = self._build_notification_dispatch()
        self._notification_handler: NotificationHandler = notification_handler
        if not self._notification_handler:
            self._notification_handler = DefaultNotificationHandler()

        self._debugstr_re = re.compile(r"thread=(\d+)\s+(cr|lf|crlf)?\s+string=(.+)")
        self._debugstr_accumulator = collections.defaultdict(str)

        self._threads: Dict[int, Thread] = {}
        self._module_table: Dict[str, Module] = {}
        self._section_table: Dict[int, Section] = {}

        self._running = True
        self._notification_queue_cv = threading.Condition()
        self._notification_queue = collections.deque()
        self._notification_processor_thread = threading.Thread(
            target=self._notification_processor_thread_main,
            name=f"Debugger Notification Processor",
        )
        self._notification_processor_thread.start()
        self._notification_channel_connected = False
        self._hello_received = False

        self._active_thread_id: Optional[int] = None
        self._last_xbdm_execution_state: Optional[str] = None

    @property
    def threads(self) -> Iterable[Thread]:
        return self._threads.values()

    @property
    def active_thread(self) -> Optional[Thread]:
        return self._threads.get(self._active_thread_id)

    @property
    def any_thread_id(self) -> int:
        """Returns the thread ID of any valid thread (preferring the active context)."""
        if not self._threads:
            return 0

        thread = self.active_thread
        if thread:
            return thread.thread_id

        return self._threads[0].thread_id

    @property
    def short_state_info(self) -> str:
        """Returns a short string indicating the current execution state."""
        items = []

        if self._last_xbdm_execution_state:
            items.append(self._last_xbdm_execution_state)

        if self._active_thread_id is not None:
            items.append("TID[%d]" % self._active_thread_id)

        return " ".join(items)

    @property
    def modules(self) -> Dict[str, Module]:
        return self._module_table

    @property
    def sections(self) -> Dict[int, Section]:
        return self._section_table

    def get_thread(self, thread_id: int) -> Optional[Thread]:
        return self._threads.get(thread_id)

    def shutdown(self):
        if self._debug_port:
            self._connection.destroy_notification_listener(self._debug_port)
        self._running = False
        self._notification_processor_thread.join()

    def attach(self):
        """Attaches this debugger instance."""

        # TODO: Check that the previous listener is still running.
        if not self._debug_port:
            listener_addr = self._connection.create_notification_listener(
                handler=self._on_notification
            )
            self._debug_port = listener_addr[1]

        self._connection.send_command(
            rdcp_command.NotifyAt(self._debug_port, debug_flag=True)
        )
        self._connection.send_command(rdcp_command.Debugger())
        self.refresh_thread_info()

    def debug_xbe(
        self, path: str, command_line: Optional[str] = None, persist: bool = False
    ):
        """Runs the given XBE and breaks at the entry address."""

        dir_name = os.path.dirname(path)
        xbe_name = os.path.basename(path)

        response = self._call(
            rdcp_command.LoadOnBootTitle(
                name=xbe_name,
                directory=dir_name,
                command_line=command_line,
                persist=persist,
            )
        )
        if not response.ok:
            print(response.pretty_message)
            return

        self._restart_and_attach()

    def clear_debug_xbe(self) -> bool:
        """Clears the previously persisted debug target XBE."""
        response = self._call(rdcp_command.LoadOnBootTitleUnpersist())
        return response.ok

    def restart(self):
        """Reboots the current XBE and breaks at the entry address."""
        self._restart_and_attach()

    def set_active_thread(self, thread_id: Optional[int]):
        self._active_thread_id = thread_id

    def go(self) -> bool:
        response = self._call(rdcp_command.Go())
        return response.ok

    def step_instruction(self) -> bool:
        thread = self.active_thread
        if not thread:
            print("No active thread context")
            return False

        if not thread.set_step_instruction_mode(True):
            print("Failed to set trap flag.")
            return False

        if not thread.continue_once():
            print("Failed to continue thread.")
            return False

        if not thread.set_step_instruction_mode(False):
            print("Failed to clear trap flag.")
            return False

        if not self.go():
            print("Failed to go.")
            return False

        return True

    def step_function(self) -> bool:
        thread = self.active_thread
        if not thread:
            print("No active thread context")
            return False

        if not thread.prepare_step_function():
            print("Failed to set funccall flag.")
            return False

        if not self.go():
            print("Failed to go.")
            return False

        return True

    def refresh_thread_info(self):
        response = self._call(rdcp_command.Threads())

        assert response.ok
        new_thread_ids = set(response.thread_ids)

        known_threads = set(self._threads.keys())

        to_remove = known_threads - new_thread_ids
        for thread_id in to_remove:
            del self._threads[thread_id]

        to_add = new_thread_ids - known_threads
        for thread_id in to_add:
            self._threads[thread_id] = Thread(thread_id, self._connection)

        to_update = new_thread_ids.intersection(known_threads)
        for thread_id in to_update:
            self._threads[thread_id].get_info()

    def get_thread_context(self) -> Optional[Thread.Context]:
        thread = self.active_thread
        if not thread:
            return None

        return thread.get_context()

    def get_full_thread_context(self) -> Optional[Thread.FullContext]:
        thread = self.active_thread
        if not thread:
            return None

        return thread.get_full_context()

    def halt(self, timeout_seconds=0.250) -> bool:
        """Halts all running threads and waits for break response."""

        self._last_xbdm_execution_state = None
        response = self._call(rdcp_command.Halt())
        if not response.ok:
            return False

        if not self.threads:
            # This should never happen as the call to Halt() should fail.
            logger.warning("Halt called on an instance with no threads!")
            return True

        # Switch context to the most appropriate stopped thread, if one exists.
        thread = self.active_thread
        if thread:
            thread.fetch_stop_reason()
        else:
            for thr in self.threads:
                if not thr.fetch_stop_reason():
                    continue
                if thr.last_stop_reason:
                    self.set_active_thread(thr.thread_id)
                    thread = thr
                    break
        if not thread:
            # Just switch to the first thread.
            self.set_active_thread(self._threads[0].thread_id)

        time_waited = 0
        if timeout_seconds and thread.last_stop_reason is None:
            wait_per_loop = 0.005
            while time_waited < timeout_seconds:
                if self._last_xbdm_execution_state:
                    break
                time.sleep(wait_per_loop)
                time_waited += wait_per_loop

            if time_waited >= timeout_seconds and not thread.fetch_stop_reason():
                logger.warning("Halt failed to result in a state update.")
                return False

        return thread.last_stop_reason is not None

    def continue_all(self, break_on_exceptions: bool = True):
        """Continues all threads."""
        for thread in self._threads.values():
            thread.continue_once(break_on_exceptions)
        return True

    def get_memory(self, address: int, length: int) -> Optional[bytes]:
        """Reads memory from the target."""
        response = self._call(rdcp_command.GetMemBinary(address, length))
        if not response.ok:
            return None
        return response.data

    def set_memory(self, address: int, data: bytes) -> bool:
        """Writes memory to the given target address."""
        response = self._call(rdcp_command.SetMem(address, data))
        return response.ok

    def add_breakpoint_at_address(self, address: int) -> bool:
        """Adds a breakpoint at the given target address."""
        response = self._call(rdcp_command.BreakAtAddress(address))
        return response.ok

    def remove_breakpoint_at_address(self, address: int) -> bool:
        """Removes a breakpoint from the given target address."""
        response = self._call(rdcp_command.BreakAtAddress(address, clear=True))
        return response.ok

    def add_read_watchpoint(self, address: int, length: int) -> bool:
        """Adds a read watchpoint on the given memory block."""
        response = self._call(rdcp_command.BreakOnRead(address, length))
        return response.ok

    def add_write_watchpoint(self, address: int, length: int) -> bool:
        """Adds a write watchpoint on the given memory block."""
        response = self._call(rdcp_command.BreakOnWrite(address, length))
        return response.ok

    def remove_read_watchpoint(self, address: int, length: int) -> bool:
        """Removes a read watchpoint on the given memory block."""
        response = self._call(rdcp_command.BreakOnRead(address, length, clear=True))
        return response.ok

    def remove_write_watchpoint(self, address: int, length: int) -> bool:
        """Removes a write watchpoint on the given memory block."""
        response = self._call(rdcp_command.BreakOnWrite(address, length, clear=True))
        return response.ok

    def _restart_and_attach(self):
        response = self._call(
            rdcp_command.Reboot(
                rdcp_command.Reboot.FLAG_STOP
                | rdcp_command.Reboot.FLAG_WAIT
                | rdcp_command.Reboot.FLAG_WARM
            )
        )
        assert response.ok

        self._notification_channel_connected = False
        self._hello_received = False

        # Wait for the connection to drop during the restart
        logger.debug("Waiting for XBOX to drop connection.")
        max_wait = 1000
        busy_wait_secs = 0.025
        while self._connection.can_process_xbdm_commands:
            time.sleep(busy_wait_secs)
            max_wait -= busy_wait_secs
            if max_wait <= 0:
                logger.error("XBOX does not appear to have rebooted, aborting.")
                return

        # Wait for XBDM to say "hello" on the debug channel
        logger.debug("Waiting for XBOX to become available.")
        max_wait = 30000
        while not self._hello_received:
            time.sleep(busy_wait_secs)
            max_wait -= busy_wait_secs
            if max_wait <= 0:
                logger.error("XBOX has not come back from reboot, aborting.")
                return

        # Attempt to reconnect the control channel.
        max_wait = 10
        self._connection.debugger__set_control_channel_state_to_connected()
        while not self._connection.connect_xbdm():
            self._connection.debugger__set_control_channel_state_to_connected()
            max_wait -= 1
            if max_wait <= 0:
                logger.error(
                    "Failed to reconnect debugger channel after restart, aborting."
                )
                return

        self.refresh_thread_info()
        self._connection.send_command(rdcp_command.Debugger())

        # Set a breakpoint at the entry to the program and continue forward
        # until it is hit.
        self._connection.send_command(rdcp_command.BreakAtStart())
        self._connection.send_command(rdcp_command.Go())

    def _build_notification_dispatch(self) -> Dict[str, Callable[[str], None]]:
        return {
            "vx!": self._process_vx,
            "debugstr ": self._process_debugstr,
            "modload ": self._process_modload,
            "sectload ": self._process_sectload,
            "create ": self._process_create_thread,
            "terminate ": self._process_terminate_thread,
            "execution ": self._process_execution_state_change,
            "break ": self._process_break,
            "data": self._process_data_break,
            "singlestep": self._process_single_step_break,
        }

    def _on_notification(self, message: str):
        self._notification_channel_connected = True

        if message == "hello":
            # Sent when XBDM reconnects after a reboot event.
            self._hello_received = True
            return

        with self._notification_queue_cv:
            self._notification_queue.appendleft(message)
            self._notification_queue_cv.notify()

    def _notification_processor_thread_main(self):
        while self._running:
            with self._notification_queue_cv:
                process = self._notification_queue_cv.wait_for(
                    lambda: len(self._notification_queue) > 0, timeout=0.1
                )
                if not process:
                    continue
                message = self._notification_queue.pop()

            handled = False
            if message == XBDMNotificationServer.CONNECTED_NOTIFICATION:
                self._hello_received = True
                continue

            for key, handler in self._notification_dispatch.items():
                if message.startswith(key):
                    handler(message[len(key) :])
                    handled = True
                    break
            if not handled:
                logger.warning(f"UNHANDLED DEBUGGER NOTIFICATION: '{message}'")

    def _process_vx(self, message):
        # 'event <Event Id="Xbe" Time="0x01d7c7c10fe720e0" Severity="1" TCR="" Description="\Device\Harddisk0\Partition2\xshell.xbe"/>'
        # 'event <Event Id="Xtl" Time="0x01d7c7c10fe7e430" Severity="1" TCR="" Description="XTL imports resolved"/>'
        self._notification_handler.vx(message)

    def _process_debugstr(self, message):
        match = self._debugstr_re.match(message)
        if not match:
            logger.error(f"FAILED TO MATCH DBGSTR: {message}")
            return

        thread_id = int(match.group(1), 0)
        text = match.group(3)

        # If the string isn't flushed, accumulate it until it is
        if not match.group(2):
            self._debugstr_accumulator[thread_id] += text
            return

        previous_buffer = self._debugstr_accumulator.get(thread_id) or ""
        self._debugstr_accumulator[thread_id] = ""
        text = previous_buffer + text

        self._notification_handler.debugstr(thread_id, text)

    def _process_modload(self, message):
        mod = Module.parse(message)
        if not mod:
            logger.error(f"FAILED TO MATCH MODLOAD: {message}")
            return
        self._module_table[mod.name] = mod
        self._notification_handler.module_load(mod)

    def _process_sectload(self, message):
        sect = Section.parse(message)
        if not sect:
            logger.error(f"FAILED TO MATCH SECTLOAD: {message}")
            return
        self._section_table[sect.index] = sect
        self._notification_handler.section_load(sect)

    def _process_create_thread(self, message):
        match = re.match(_match_hex("thread"), message)
        if not match:
            logger.error(f"FAILED TO MATCH CREATE: {message}")
            return

        thread_id = int(match.group(1), 0)
        if not self._connection.can_process_xbdm_commands:
            logger.info(
                f"Suppressing create thread({thread_id}) notification as control channel is not up yet."
            )
            return

        thread = Thread(thread_id, self._connection)
        self._threads[thread_id] = thread
        thread.get_info()
        self._notification_handler.create_thread(thread_id, thread.start_addr)

    def _process_terminate_thread(self, message):
        match = re.match(_match_hex("thread"), message)
        if not match:
            logger.error(f"FAILED TO MATCH CREATE: {message}")
            return

        thread_id = int(match.group(1), 0)
        self._threads.pop(thread_id)
        self._notification_handler.terminate_thread(thread_id)

    def _process_execution_state_change(self, message):
        self._last_xbdm_execution_state = message

        if message == "rebooting":
            logger.debug("Received reboot notification")
            self._hello_received = False
            self._module_table.clear()
            self._section_table.clear()
            return
        # rebooting
        # pending
        # started
        # stopped
        self._notification_handler.execution_state_change(message)

    _BREAK_RE = re.compile(
        r"\s+".join([_match_hex(x) for x in ["addr", "thread"]]) + "\s+(.+)?"
    )

    def _process_break(self, message: str):
        match = self._BREAK_RE.match(message)
        if not match:
            logger.error(f"FAILED TO MATCH BREAK: {message}")
            return

        address = int(match.group(1), 0)
        thread_id = int(match.group(2), 0)
        reason = match.group(3) or ""

        thread = self._threads.get(thread_id)
        if not thread:
            thread = Thread(thread_id, self._connection)
            self._threads[thread_id] = thread
            thread.get_info()

        thread.last_known_address = address
        self._active_thread_id = thread_id

        logger.debug("!!! BREAK !!! %d @ 0x%X %s" % (thread_id, address, reason))
        self._notification_handler.breakpoint(thread_id, address, reason)

    _DATA_BREAK_RE = re.compile(
        r"\s+".join([_match_hex(x) for x in ["(read|write|execute)", "addr", "thread"]])
        + "\s+(.+)?"
    )

    def _process_data_break(self, message: str):
        match = self._DATA_BREAK_RE.match(message)
        if not match:
            logger.error(f"FAILED TO MATCH DATA BREAK: {message}")
            return

        access = match.group(1)
        accessed_address = int(match.group(2), 0)
        access_instruction_pointer = int(match.group(3), 0)
        thread_id = int(match.group(4), 0)
        reason = match.group(5) or ""

        thread = self._threads.get(thread_id)
        if not thread:
            thread = Thread(thread_id, self._connection)
            self._threads[thread_id] = thread
            thread.get_info()

        thread.last_known_address = accessed_address
        self._active_thread_id = thread_id

        logger.debug(
            "!!! DATA BREAK !!! %d: %s@0x%08X @ 0x%X %s"
            % (thread_id, access, access_instruction_pointer, accessed_address, reason)
        )
        self._notification_handler.data_breakpoint(
            thread_id, access, access_instruction_pointer, accessed_address, reason
        )

    _SINGLE_STEP_RE = re.compile(
        r"\s+".join([_match_hex(x) for x in ["addr", "thread"]]) + "\s+(.+)?"
    )

    def _process_single_step_break(self, message: str):
        match = self._SINGLE_STEP_RE.match(message)
        if not match:
            logger.error(f"FAILED TO MATCH SINGLESTEP: {message}")
            return

        address = int(match.group(1), 0)
        thread_id = int(match.group(2), 0)

        thread = self._threads.get(thread_id)
        if not thread:
            thread = Thread(thread_id, self._connection)
            self._threads[thread_id] = thread
            thread.get_info()

        thread.last_known_address = address
        self._active_thread_id = thread_id

        logger.debug("!!! SINGLESTEP !!! %d @ 0x%X" % (thread_id, address))
        self._notification_handler.step(thread_id, address)
