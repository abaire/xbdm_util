"""Manages a transport interface to an XBDM."""
from __future__ import annotations

import logging
import select
import socket
import time
import threading
from typing import Callable
from typing import Optional
from typing import Tuple

from . import rdcp_command
from . import remote_debugger_server
from . import xbdm_notification_server
from . import xbdm_transport
from net import ip_transport

SELECT_TIMEOUT_SECS = 0.25
logger = logging.getLogger(__name__)


class XBDMBridge:
    """Manages an XBDM connection."""

    def __init__(self, xbox_name: str, xbox_addr: Tuple[str, int]):
        self.xbox_name: str = xbox_name
        self.xbox_addr: Tuple[str, int] = xbox_addr

        # The IP, port at which remote debuggers can connect.
        self._remote_listen_addr: Optional[Tuple[str, int]] = None

        # Method to construct a transport when a remote debugger connects to this
        # bridge.
        self._remote_handler_constructor: Optional[
            Callable[
                [XBDMBridge, socket.socket, Tuple[str, int]],
                Optional[ip_transport.IPTransport],
            ]
        ] = None

        # Primary channel to XBDM.
        self._xbdm: Optional[xbdm_transport.XBDMTransport] = None
        self._notification_listener: [
            xbdm_notification_server.XBDMNotificationServer
        ] = None
        self._remote_listener: Optional[
            remote_debugger_server.RemoteDebuggerServer
        ] = None

        self._running: bool = False
        self._thread: Optional[threading.Thread] = None

        self._startup()

    def shutdown(self):
        logger.debug(f"Shutting down bridge to {self.xbox_info}")
        self._running = False
        self._thread.join()
        self._thread = None
        self._close()

    @property
    def xbox_info(self) -> str:
        return f"{self.xbox_name}@{self.xbox_addr[0]}:{self.xbox_addr[1]}"

    @property
    def can_process_xbdm_commands(self) -> bool:
        return self._xbdm.can_process_commands

    @property
    def remote_listen_addr(self) -> Optional[Tuple[int, str]]:
        return self._remote_listen_addr

    def reconnect(self, connect_attempts: int = 4) -> bool:
        """Drops and restores the connections to the target.

        Returns True if the reconnection was successful"""
        self.shutdown()
        logger.info("Reconnecting...")
        self._startup()
        for i in range(connect_attempts):
            if self.connect_xbdm():
                return True
        return self.can_process_xbdm_commands

    def _startup(self):
        self._xbdm = xbdm_transport.XBDMTransport(f"XBDM-{self.xbox_info}")
        if self._remote_listen_addr and self._remote_handler_constructor:
            self._create_remote_listener()

        self._running = True
        self._thread = threading.Thread(
            target=self._thread_main, name=f"Bridge {self.xbox_info}"
        )
        self._thread.start()

    def _close(self):
        self._running = False

        if self._xbdm:
            self._xbdm.close()

        if self._remote_listener:
            self._remote_listener.close()

        if self._notification_listener:
            self._notification_listener.close()

    def connect_xbdm(self) -> bool:
        if self._xbdm.can_process_commands:
            return True

        if self._xbdm.connected:
            # TODO: Wait on a condition variable until the connection response is received.
            time.sleep(1)
            return self._xbdm.can_process_commands

        ret = self._connect_to_xbdm()
        if ret:
            # TODO: Wait on a condition variable until the connection response is received.
            time.sleep(1)
            pass

        return self._xbdm.can_process_commands

    def connect_xbdm_async(self, callback: Callable[[bool], None]) -> None:
        threading.Thread(
            target=lambda bridge: callback(bridge.connect_xbdm()),
            name=f"connect_xbdm_async {self.xbox_info}",
            args=(self,),
        ).start()

    def send_command(self, cmd: rdcp_command.RDCPCommand) -> bool:
        return self._xbdm.send_command(cmd)

    def create_remote_listener(
        self,
        listen_addr: Tuple[str, int],
        on_connected: Optional[
            Callable[
                [XBDMBridge, socket.socket, Tuple[str, int]],
                Optional[ip_transport.IPTransport],
            ]
        ],
    ):
        """Starts a listener for remote debugger connections."""

        if self._remote_listen_addr:
            logger.error("Remote listener already started, ignoring")
            return

        self._remote_listen_addr = listen_addr
        self._remote_connected_handler = on_connected

        self._create_remote_listener()

    def destroy_remote_listener(self):
        """Closes the remote debugger listener."""
        if not self._remote_listener:
            return

        self._remote_listener.close()
        self._remote_listener = None

    def create_notification_listener(
        self, port: Optional[int] = None, handler: Callable[[str], None] = None
    ) -> Optional[Tuple[str, int]]:
        """Creates a new dedicated notification listener on the given port."""
        if self._notification_listener:
            logger.error(
                f"Notification listener already running at {self._notification_listener.addr}"
            )
            return None

        if not port:
            port = 0
        server = xbdm_notification_server.XBDMNotificationServer(
            ("", port), handler=handler
        )
        self._notification_listener = server
        return server.addr

    def destroy_notification_listener(self):
        """Closes the notification listener."""
        if not self._notification_listener:
            return

        self._notification_listener.close()
        self._notification_listener = None

    def debugger__set_control_channel_state_to_connected(self):
        """Marks the underlying XBDMTransport as fully connected if it has a socket connection.

        This is necessary as XBDM will not send a connection event when
        restarting with a debug notification channel already in place.
        """
        self._xbdm.debug__notify_connected()

    def _thread_main(self):
        while self._running:
            readable = []
            writable = []
            exceptional = []

            self._xbdm.select(readable, writable, exceptional)
            if self._notification_listener:
                self._notification_listener.select(readable, writable, exceptional)
            if self._remote_listener:
                self._remote_listener.select(readable, writable, exceptional)

            readable, writable, exceptional = select.select(
                readable, writable, exceptional, SELECT_TIMEOUT_SECS
            )

            if self._notification_listener:
                try:
                    self._notification_listener.process(readable, writable, exceptional)
                except ConnectionResetError:
                    logger.error(f"Exception from notification listener, closing...")
                    self._notification_listener.close()
                    self._notification_listener = None

            if self._remote_listener:
                try:
                    self._remote_listener.process(readable, writable, exceptional)
                except ConnectionResetError:
                    logger.error(f"Exception from remote listener, closing...")
                    self._remote_listener.close()
                    self._remote_listener = None

            try:
                if not self._xbdm.process(readable, writable, exceptional):
                    self._xbdm.close()
                    print("XBDM connection closed")
            except ConnectionResetError:
                print("XBDM connection closed remotely")
                self._xbdm.close()

        logger.debug(f"Shutting down connection for {self.xbox_info}")
        self._close()

    def _create_remote_listener(self):
        self._remote_listener = remote_debugger_server.RemoteDebuggerServer(
            self.xbox_info, self._remote_listen_addr, self._on_remote_debugger_accepted
        )
        # Update the listen_addr in case a port or IP was left unset.
        self._remote_listen_addr = self._remote_listener.addr
        port = self._remote_listener.addr[1]
        logger.info(f"Listening at port {port} and bridging to {self.xbox_info}")

    def _on_remote_debugger_accepted(
        self, remote: socket.socket, remote_addr: Tuple[str, int]
    ) -> Optional[ip_transport.IPTransport]:
        transport: Optional[ip_transport.IPTransport] = self._remote_connected_handler(
            self, remote, remote_addr
        )
        if not transport:
            logger.debug(f"Denied bridge request from {remote_addr}")
        return transport

    def await_empty_queue(self) -> None:
        assert threading.current_thread() != self._thread
        # TODO: Use condition variables instead of spinning.
        while self._xbdm.has_buffered_data:
            time.sleep(0.05)

    def _connect_to_xbdm(self, timeout_seconds: int = 15) -> bool:
        logger.info(f"Connecting to XBDM {self.xbox_addr}")
        try:
            sock = socket.create_connection(self.xbox_addr, timeout_seconds)
        except ConnectionRefusedError:
            logger.error(f"Failed to connect to XBDM {self.xbox_info}")
            return False
        except OSError as err:
            logger.error(f"Failed to connect to XBDM {self.xbox_info} {err}")
            return False

        logger.info(f"Socket connected to XBDM {self.xbox_info}")
        sock.setblocking(False)
        self._xbdm.set_connection(sock, self.xbox_addr)
        return True
