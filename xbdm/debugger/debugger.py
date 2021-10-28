"""Provides higher level functions for step-debugging functionality."""
from __future__ import annotations

import collections
import logging
import re
import threading
import time
from typing import Any
from typing import Callable
from typing import Dict
from typing import Iterable
from typing import List
from typing import Mapping
from typing import Optional

from .notification_handler import DefaultNotificationHandler
from .notification_handler import NotificationHandler
from .module import Module
from .section import Section
from .thread import Thread
from .util import match_hex
from .xbdm_client import _XBDMClient
from xbdm import rdcp_command
from xbdm.xbdm_bridge import XBDMBridge
from xbdm.xbdm_notification_server import XBDMNotificationServer

logger = logging.getLogger(__name__)


class Debugger(_XBDMClient):
    """Provides high level debugger functionality."""

    class _MemoryRegion:
        def __init__(self, walkmem_result: Mapping[str, Any]):
            self.start = walkmem_result["base_address"]
            self.size = walkmem_result["size"]
            self.protection = walkmem_result["protection_flags"]
            self.end = self.start + self.size

        def __str__(self):
            return "%s 0x%08X - 0x%08X [%d] FL:0x%08X" % (
                self.__class__.__name__,
                self.start,
                self.end,
                self.size,
                self.protection,
            )

        def contains(self, start: int, size: int) -> bool:
            return start >= self.start and (start + size) <= self.end

    def __init__(
        self,
        connection: XBDMBridge,
        notification_handler: Optional[NotificationHandler] = None,
    ):
        super().__init__(connection)
        self._debug_port = None

        self._notification_dispatch = self._build_notification_dispatch()
        self._notification_handler: NotificationHandler = self.set_notification_handler(
            notification_handler
        )

        self._debugstr_re = re.compile(r"thread=(\d+)\s+(cr|lf|crlf)?\s+string=(.+)")
        self._debugstr_accumulator = collections.defaultdict(str)

        self._threads: Dict[int, Thread] = {}
        self._module_table: Dict[str, Module] = {}
        self._section_table: Dict[int, Section] = {}
        self._memory_regions: List[Debugger._MemoryRegion] = []

        self._running = True
        self._notification_queue_cv = threading.Condition()
        self._notification_queue = collections.deque()
        self._notification_processor_thread = threading.Thread(
            target=self._notification_processor_thread_main,
            name=f"Debugger Notification Processor",
        )
        self._notification_processor_thread.start()
        self._notification_channel_connected = False

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
            tid: int = self._active_thread_id or 0  # Suppress pylint warning.
            items.append("TID[%d]" % tid)

        return " ".join(items)

    @property
    def modules(self) -> Dict[str, Module]:
        return self._module_table

    @property
    def sections(self) -> Dict[int, Section]:
        return self._section_table

    def set_notification_handler(
        self, handler: Optional[NotificationHandler] = None
    ) -> NotificationHandler:
        self._notification_handler = handler or DefaultNotificationHandler()

    def get_thread(self, thread_id: int) -> Optional[Thread]:
        return self._threads.get(thread_id)

    def shutdown(self):
        if self._debug_port:
            self._bridge.destroy_notification_listener()
        self._running = False
        self._notification_processor_thread.join()

    def attach(self):
        """Attaches this debugger instance."""

        # TODO: Check that the previous listener is still running.
        if not self._debug_port:
            listener_addr = self._bridge.create_notification_listener(
                handler=self._on_notification
            )
            self._debug_port = listener_addr[1]

        self._bridge.send_command(
            rdcp_command.NotifyAt(self._debug_port, debug_flag=True)
        )
        self._bridge.send_command(rdcp_command.Debugger())
        self.refresh_thread_info()
        self.refresh_memory_map()

    def debug_xbe(
        self,
        path: str,
        command_line: Optional[str] = None,
        persist: bool = False,
        wait_before_start: bool = False,
    ):
        """Runs the given XBE and breaks at the entry address.

        If `wait_before_start` is set, a Go command must be sent before execution will
        halt at the entry point.
        """

        flags = rdcp_command.Reboot.FLAG_WAIT | rdcp_command.Reboot.FLAG_WARM
        if wait_before_start:
            flags |= rdcp_command.Reboot.FLAG_STOP
        self._restart_and_reconnect(flags)
        self.clear_debug_xbe()

        last_slash = path.rfind("\\")
        xbe_name = path[last_slash + 1 :]
        # For convenience, treat any path to a non-xbe as a directory that contains a
        # default.xbe target.
        dir_name = path[: last_slash + 1]
        if not xbe_name.lower().endswith("xbe"):
            dir_name += xbe_name
            xbe_name = "default.xbe"

        if not dir_name[-1] == "\\":
            dir_name += "\\"

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

        self._bridge.send_command(rdcp_command.BreakAtStart())
        if not wait_before_start:
            self._bridge.send_command(rdcp_command.Go())

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
            self._threads[thread_id] = Thread(thread_id, self._bridge)

        to_update = new_thread_ids.intersection(known_threads)
        for thread_id in to_update:
            self._threads[thread_id].get_info()

    def refresh_memory_map(self):
        response = self._call(rdcp_command.WalkMem())
        if not response.ok:
            logger.error("Failed to retrieve memory map!")
            return

        self._memory_regions = [
            self._MemoryRegion(region) for region in response.regions
        ]

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

        if not self._validate_memory_access(address, length):
            return None

        response = self._call(rdcp_command.GetMemBinary(address, length))
        if not response.ok:
            return None
        return response.data

    def set_memory(self, address: int, data: bytes) -> bool:
        """Writes memory to the given target address."""
        if not self._validate_memory_access(address, len(data)):
            return False
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

    def _restart_and_attach(
        self,
        reboot_flags: int = rdcp_command.Reboot.FLAG_STOP
        | rdcp_command.Reboot.FLAG_WAIT
        | rdcp_command.Reboot.FLAG_WARM,
    ):
        self._restart_and_reconnect(reboot_flags)
        # Set a breakpoint at the entry to the program and continue forward
        # until it is hit.
        self._bridge.send_command(rdcp_command.BreakAtStart())
        self._bridge.send_command(rdcp_command.Go())

    def _restart_and_reconnect(
        self, reboot_flags: int, wait_for_notification_channel: bool = True
    ) -> bool:
        response = self._call(rdcp_command.Reboot(reboot_flags))
        assert response.ok

        self._notification_channel_connected = False

        # Wait for the connection to drop during the restart
        logger.debug("Waiting for XBOX to drop connection.")
        max_wait_secs = 10
        busy_wait_secs = 0.025
        while self._bridge.can_process_xbdm_commands:
            time.sleep(busy_wait_secs)
            max_wait_secs -= busy_wait_secs
            if max_wait_secs <= 0:
                logger.error("XBOX does not appear to have rebooted, aborting.")
                return False

        # Wait for XBDM to say "hello" on the debug channel
        if wait_for_notification_channel:
            logger.debug("Waiting for XBOX to become available.")
            max_wait_secs = 10
            while not self._notification_channel_connected:
                time.sleep(busy_wait_secs)
                max_wait_secs -= busy_wait_secs
                if max_wait_secs <= 0:
                    logger.error(
                        "XBOX has not come back from reboot, attempting reconnect."
                    )
                    break

        # Attempt to reconnect the control channel.
        max_wait_secs = 10
        self._bridge.debugger__set_control_channel_state_to_connected()
        while not self._bridge.connect_xbdm():
            self._bridge.debugger__set_control_channel_state_to_connected()
            max_wait_secs -= 1
            if max_wait_secs <= 0:
                logger.error(
                    "Failed to reconnect debugger channel after restart, aborting."
                )
                return False

        self.refresh_thread_info()
        self._bridge.send_command(rdcp_command.Debugger())
        return True

    def _validate_memory_access(self, address: int, length: int) -> bool:
        if not self._memory_regions:
            logger.warning("No memory regions mapped, assuming access is OK.")
            return True

        # TODO: Validate that the region is writable if necessary.
        for region in self._memory_regions:
            if region.contains(address, length):
                return True

        return False

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
            "data ": self._process_data_break,
            "singlestep ": self._process_single_step_break,
            "exception ": self._process_exception,
        }

    def _on_notification(self, message: str):
        self._notification_channel_connected = True

        if message == "hello":
            # Sent when XBDM reconnects after a reboot event.
            self._notification_channel_connected = True
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
                self._notification_channel_connected = True
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

        # TODO: Queue a request to recreate the memory map to load flags.
        # The memory map load can't be done from the notification thread as it's
        # possible that the control channel is not connected.
        region = self._MemoryRegion(
            {
                "base_address": mod.base_address,
                "size": mod.size,
                "protection_flags": 0x00,
            }
        )
        self._memory_regions.append(region)
        self._notification_handler.module_load(mod)

    def _process_sectload(self, message):
        sect = Section.parse(message)
        if not sect:
            logger.error(f"FAILED TO MATCH SECTLOAD: {message}")
            return
        self._section_table[sect.index] = sect
        self._notification_handler.section_load(sect)

    def _process_create_thread(self, message):
        match = re.match(match_hex("thread"), message)
        if not match:
            logger.error(f"FAILED TO MATCH CREATE: {message}")
            return

        thread_id = int(match.group(1), 0)
        if not self._bridge.can_process_xbdm_commands:
            logger.info(
                f"Suppressing create thread({thread_id}) notification as control channel is not up yet."
            )
            return

        try:
            thread = Thread(thread_id, self._bridge)
            self._threads[thread_id] = thread
            thread.get_info()
            self._notification_handler.create_thread(thread_id, thread.start_addr)
        except ConnectionResetError:
            # Assume that a reconnect will be performed and will fetch the thread info.
            logger.info(
                f"Suppressing create thread({thread_id}) notification as control channel is not up yet."
            )
            return

    def _process_terminate_thread(self, message):
        match = re.match(match_hex("thread"), message)
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
            self._notification_channel_connected = False
            self._module_table.clear()
            self._section_table.clear()
            return
        # rebooting
        # pending
        # started
        # stopped
        self._notification_handler.execution_state_change(message)

    _BREAK_RE = re.compile(
        r"\s+".join([match_hex(x) for x in ["addr", "thread"]]) + r"\s*(.+)?"
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
            thread = Thread(thread_id, self._bridge)
            self._threads[thread_id] = thread
            thread.get_info()

        thread.last_known_address = address
        self._active_thread_id = thread_id

        logger.debug("!!! BREAK !!! %d @ 0x%X %s" % (thread_id, address, reason))
        self._notification_handler.breakpoint(thread_id, address, reason)

    _DATA_BREAK_RE = re.compile(
        r"\s+".join([match_hex(x) for x in ["(read|write|execute)", "addr", "thread"]])
        + r"\s*(.+)?"
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
            thread = Thread(thread_id, self._bridge)
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
        r"\s+".join([match_hex(x) for x in ["addr", "thread"]])
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
            thread = Thread(thread_id, self._bridge)
            self._threads[thread_id] = thread
            thread.get_info()

        thread.last_known_address = address
        self._active_thread_id = thread_id

        logger.debug("!!! SINGLESTEP !!! %d @ 0x%X" % (thread_id, address))
        self._notification_handler.step(thread_id, address)

    _EXCEPTION_RE = re.compile(
        r"\s+".join([match_hex(x) for x in ["code", "thread", "address", "read"]])
        + r"\s*(.+)?"
    )

    def _process_exception(self, message: str):
        match = self._EXCEPTION_RE.match(message)
        if not match:
            logger.error(f"FAILED TO MATCH EXCEPTION: {message}")
            return

        code = int(match.group(1), 0)
        thread_id = int(match.group(2), 0)
        address = int(match.group(3), 0)
        read = int(match.group(4), 0)
        extra = match.group(5)

        logger.debug(
            "!!! EXCEPTION !!! %d code 0x%X @ 0x%X read: 0x%X extra: '%s'"
            % (thread_id, code, address, read, extra)
        )
        self._notification_handler.exception(thread_id, code, address, read, extra)
