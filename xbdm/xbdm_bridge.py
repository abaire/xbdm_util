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
from . import xbdm_bridge_remote_server
from . import xbdm_notification_server
from . import xbdm_transport
from net import ip_transport

SELECT_TIMEOUT_SECS = 0.25
logger = logging.getLogger(__name__)


class XBDMBridge:
    """Manages an XBDM connection."""

    def __init__(
        self,
        listen_addr: Optional[Tuple[str, int]],
        xbox_name: str,
        xbox_addr: Tuple[str, int],
        remote_connected_handler: Optional[
            Callable[
                [XBDMBridge, socket.socket, Tuple[str, int]],
                Optional[ip_transport.IPTransport],
            ]
        ] = None,
    ):
        self.remote_listen_addr: Optional[Tuple[str, int]] = listen_addr
        self._remote_connected_handler = remote_connected_handler
        self.xbox_name: str = xbox_name
        self.xbox_addr: Tuple[str, int] = xbox_addr

        self._xbdm: Optional[xbdm_transport.XBDMTransport] = None
        self._dedicated_channels = set()

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

    def reconnect(self, connect_attempts: int = 4) -> bool:
        """Drops and restores the connection to the target.

        Returns True if the reconnection was successful"""
        self.shutdown()
        logger.info("Reconnecting...")
        self._startup()
        for i in range(connect_attempts):
            if self.connect_xbdm():
                return True
        return self.can_process_xbdm_commands

    def _startup(self):
        if self.remote_listen_addr is not None and self._remote_connected_handler:
            server = xbdm_bridge_remote_server.XBDMBridgeRemoteServer(
                self.xbox_info, self.remote_listen_addr, self._on_remote_bridge_accepted
            )
            # Update the listen_addr in case a port or IP was left unset.
            self.remote_listen_addr = server.addr
            self._dedicated_channels.add(server)
            logger.info(
                f"Listening at port {server.addr[1]} and bridging to {self.xbox_info}"
            )

        self._xbdm = xbdm_transport.XBDMTransport("XBDM")

        self._running = True
        self._thread = threading.Thread(
            target=self._thread_main, name=f"Bridge {self.xbox_info}"
        )
        self._thread.start()

    def _close(self):
        self._running = False

        if self._xbdm:
            self._xbdm.close()

        for connection in self._dedicated_channels:
            connection.close()
        self._dedicated_channels.clear()

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

    def create_notification_listener(
        self, port: Optional[int] = None, handler: Callable[[str], None] = None
    ) -> Tuple[str, int]:
        """Creates a new dedicated notification listener on the given port."""
        if not port:
            port = 0
        server = xbdm_notification_server.XBDMNotificationServer(
            ("", port), handler=handler
        )
        self._dedicated_channels.add(server)
        return server.addr

    def destroy_notification_listener(self, port: int):
        """Closes an existing dedicated notification listener."""
        channels = set(self._dedicated_channels)
        for transport in channels:
            if not isinstance(
                transport, xbdm_notification_server.XBDMNotificationServer
            ):
                continue
            if transport.addr[1] != port:
                continue

            transport.close()

    def broadcast_notification(self, message: str) -> None:
        channels = set(self._dedicated_channels)
        for channel in channels:
            channel.broadcast(bytes(message, "utf-8"))

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

            for connection in self._dedicated_channels:
                connection.select(readable, writable, exceptional)

            readable, writable, exceptional = select.select(
                readable, writable, exceptional, SELECT_TIMEOUT_SECS
            )

            closed_channels = set()
            for connection in self._dedicated_channels:
                if not connection.process(readable, writable, exceptional):
                    closed_channels.add(connection)
            self._dedicated_channels -= closed_channels

            try:
                if not self._xbdm.process(readable, writable, exceptional):
                    self._xbdm.close()
                    print("XBDM connection closed")
            except ConnectionResetError as e:
                self._xbdm.close()

        logger.debug(f"Shutting down connection for {self.xbox_info}")
        self._close()

    def _on_remote_bridge_accepted(
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
