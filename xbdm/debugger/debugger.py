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
        "control": control,
        "status": status,
        "tag": tag,
        "error_offset": error_offset,
        "error_selector": error_selector,
        "data_offset": data_offset,
        "data_selector": data_selector,
        "Cr0NpxState": cr0NpxState,
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

            self.ext_register_data = None
            if ext_registers:
                self.ext_register_data = _parse_ext_registers(ext_registers)

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
        response = self._call(
            rdcp_command.GetContext(self.thread_id, enable_full=True, enable_fp=True)
        )
        if not response.ok:
            return None
        return self.Context(response.registers)

    def get_full_context(self) -> Optional[FullContext]:
        response = self._call(
            rdcp_command.GetContext(self.thread_id, enable_full=True, enable_fp=True)
        )
        if not response.ok:
            return None

        basic_registers = response.registers
        ext_registers = None
        response = self._call(rdcp_command.GetExtContext(self.thread_id))
        if response.ok:
            ext_registers = response.data

        return self.FullContext(basic_registers, ext_registers)

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


class Debugger(_XBDMClient):
    """Provides high level debugger functionality."""

    def __init__(self, connection: XBDMBridge):
        super().__init__(connection)
        self._debug_port = None

        self._notification_handler_map = self._build_notification_handler_map()

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

    def halt(self) -> bool:
        """Halts all running threads."""
        response = self._call(rdcp_command.Halt())
        return response.ok

    def continue_all(self, break_on_exceptions: bool = True):
        """Continues all threads."""
        for thread in self._threads.values():
            thread.continue_once(break_on_exceptions)
        return True

    def _restart_and_attach(self):
        response = self._call(
            rdcp_command.Reboot(
                rdcp_command.Reboot.FLAG_STOP | rdcp_command.Reboot.FLAG_WAIT
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

        self._connection.send_command(rdcp_command.Debugger())

        # Set a breakpoint at the entry to the program and continue forward
        # until it is hit.
        self._connection.send_command(rdcp_command.BreakAtStart())
        self._connection.send_command(rdcp_command.Go())

    def _build_notification_handler_map(self) -> Dict[str, Callable[[str], None]]:
        return {
            "vx!": self._process_vx,
            "debugstr ": self._process_debugstr,
            "modload ": self._process_modload,
            "sectload ": self._process_sectload,
            "create ": self._process_create_thread,
            "execution ": self._process_execution_state_change,
            "break ": self._process_break,
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
            for key, handler in self._notification_handler_map.items():
                if message.startswith(key):
                    handler(message[len(key) :])
                    handled = True
                    break
            if not handled:
                logger.warning(f"UNHANDLED DEBUGGER NOTIFICATION: '{message}'")

    def _process_vx(self, message):
        print(f"VX: {message}")
        # 'event <Event Id="Xbe" Time="0x01d7c7c10fe720e0" Severity="1" TCR="" Description="\Device\Harddisk0\Partition2\xshell.xbe"/>'
        # 'event <Event Id="Xtl" Time="0x01d7c7c10fe7e430" Severity="1" TCR="" Description="XTL imports resolved"/>'

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

        print("DBG[%03d]> %s" % (thread_id, text))

    def _process_modload(self, message):
        mod = Module.parse(message)
        if not mod:
            logger.error(f"FAILED TO MATCH MODLOAD: {message}")
            return
        self._module_table[mod.name] = mod

    def _process_sectload(self, message):
        sect = Section.parse(message)
        if not sect:
            logger.error(f"FAILED TO MATCH SECTLOAD: {message}")
            return
        self._section_table[sect.index] = sect

    def _process_create_thread(self, message):
        print(f"CREATE_THREAD: {message}")

        match = re.match(_match_hex("thread"), message)
        if not match:
            logger.error(f"FAILED TO MATCH CREATE: {message}")
            return

        thread_id = int(match.group(1), 0)
        thread = Thread(thread_id, self._connection)
        self._threads[thread_id] = thread
        thread.get_info()

    def _process_execution_state_change(self, message):
        self._last_xbdm_execution_state = message

        if message == "rebooting":
            logger.debug("Received reboot notification")
            self._hello_received = False
            self._module_table.clear()
            self._section_table.clear()
            return
        print(f"EXECUTION STATE CHANGE: {message}")
        # rebooting
        # pending
        # started
        # stopped

    _BREAK_RE = re.compile(
        r"\s+".join([_match_hex(x) for x in ["addr", "thread"]]) + "\s+(.+)"
    )

    def _process_break(self, message):
        match = self._BREAK_RE.match(message)
        if not match:
            logger.error(f"FAILED TO MATCH BREAK: {message}")
            return

        address = int(match.group(1), 0)
        thread_id = int(match.group(2), 0)
        reason = match.group(3)

        thread = self._threads.get(thread_id)
        if not thread:
            thread = Thread(thread_id, self._connection)
            self._threads[thread_id] = thread
            thread.get_info()

        thread.last_known_address = address
        self._active_thread_id = thread_id

        logger.debug("!!! BREAK !!! %d @ 0x%X %s" % (thread_id, address, reason))
