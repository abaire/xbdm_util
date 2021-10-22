"""Provides higher level functions for step-debugging functionality."""
from __future__ import annotations

import logging
import time

from xbdm import rdcp_command
from xbdm.xbdm_connection import XBDMConnection

from typing import Dict
from typing import Optional

logger = logging.getLogger(__name__)


class Thread:
    """Encapsulates information about a thread."""

    def __init__(self, thread_id: int, connection: XBDMConnection):
        self.thread_id = thread_id
        self._connection = connection

        self.suspended: Optional[bool] = None
        self.priority: Optional[int] = None
        self.thread_local_storage_addr: Optional[int] = None
        self.start_addr: Optional[int] = None
        self.base_addr: Optional[int] = None
        self.limit: Optional[int] = None
        self.create_time: Optional[int] = None

        self.get_info()

    def get_info(self):
        self._connection.send_rdcp_command(
            rdcp_command.ThreadInfo(self.thread_id, self._on_thread_info)
        )

    def _on_thread_info(self, response: rdcp_command.ThreadInfo.Response):
        assert response.ok

        self.suspended = response.suspend
        self.priority = response.priority
        self.thread_local_storage_addr = response.tlsbase
        self.start_addr = response.start
        self.base_addr = response.base
        self.limit = response.limit
        # TODO: Convert to a unix timestmap for ease of display.
        self.create_time = response.create


class Debugger:
    """Provides high level debugger functionality."""

    def __init__(self, connection: XBDMConnection):
        self._connection = connection
        self._debug_port = None

        self._threads: Dict[int, Thread] = {}
        self._notification_channel_connected = False
        self._hello_received = False

    def shutdown(self):
        if self._debug_port:
            self._connection.destroy_notification_listener(self._debug_port)

    def attach(self):
        """Attaches this debugger instance."""

        # TODO: Check that the previous listener is still running.
        if not self._debug_port:
            listener_addr = self._connection.create_notification_listener(
                handler=self._on_notification
            )
            self._debug_port = listener_addr[1]

        self._connection.send_rdcp_command(rdcp_command.NotifyAt(self._debug_port))
        self._connection.send_rdcp_command(rdcp_command.Debugger())
        self._connection.await_empty_queue()

        self._connection.send_rdcp_command(rdcp_command.Threads(self._on_threads))

    def break_at_start(self):
        """Reboots the current XBE and breaks at the entry address."""
        self._connection.send_rdcp_command(
            rdcp_command.Reboot(
                rdcp_command.Reboot.FLAG_STOP | rdcp_command.Reboot.FLAG_WAIT
            )
        )
        self._connection.await_empty_queue()

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
        max_wait = 60000
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

        self._connection.send_rdcp_command(rdcp_command.Debugger())

        # Set a breakpoint at the entry to the program and continue forward
        # until it is hit.
        self._connection.send_rdcp_command(rdcp_command.BreakAtStart())
        self._connection.send_rdcp_command(rdcp_command.Go())

    def _on_notification(self, message: str):
        logger.debug(f"DEBUGGER NOTIFICATION: '{message}'")
        self._notification_channel_connected = True

        if message == "hello":
            # Sent when XBDM reconnects after a reboot event.
            self._hello_received = True
            return

    def _on_threads(self, response: rdcp_command.Threads.Response):
        assert response.ok

        thread_ids = set(response.thread_ids)
        known_threads = set(self._threads.keys())

        to_remove = known_threads - thread_ids
        for thread_id in to_remove:
            del self._threads[thread_id]

        to_add = thread_ids - known_threads
        for thread_id in to_add:
            self._threads[thread_id] = Thread(thread_id, self._connection)

        to_update = thread_ids.union(known_threads)
        for thread_id in to_update:
            self._threads[thread_id].get_info()
