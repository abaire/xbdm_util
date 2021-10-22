from __future__ import annotations

import logging
import socket
from typing import Optional
from typing import Tuple

from . import ip_transport

logger = logging.getLogger(__name__)


class NotificationTransport(ip_transport.IPTransport):
    """Takes ownership of a socket and reads it in notification mode."""

    TERMINATOR = b"\r\n"

    def __init__(
        self,
        name: str,
        sock: socket.socket,
        addr: Tuple[str, int],
        read_buffer: Optional[bytearray] = None,
    ):
        super().__init__(self._process_notification_data, f"! {name}")

        # Take over the socket from the existing transport.
        self._sock = sock
        self.addr = addr
        if read_buffer is not None:
            self._read_buffer = read_buffer

    def _process_notification_data(self, transport: ip_transport.IPTransport):
        terminator_len = len(self.TERMINATOR)
        terminator = transport.read_buffer.find(self.TERMINATOR)
        while terminator >= 0:
            message = transport.read_buffer[:terminator]
            print(f"{self.name}: {message.decode('utf-8')}")

            transport.shift_read_buffer(terminator + terminator_len)
            terminator = transport.read_buffer.find(self.TERMINATOR)


class NotificationServer(ip_transport.IPTransport):
    """Creates a listener that will manage NotificationTransport connections."""

    def __init__(self, addr: Tuple[str, int], name: str = ""):
        super(NotificationServer, self).__init__(None, name)
        self.addr = addr
        self._sock = socket.create_server(addr, backlog=1)

    def process(
        self,
        readable: [socket.socket],
        writable: [socket.socket],
        exceptional: [socket.socket],
    ) -> bool:
        self._process_sub_connections(readable, writable, exceptional)

        if not self._sock:
            return True

        if self._sock in exceptional:
            if self.name:
                logger.info(
                    f"Socket exception in IPTransport {self.name} to {self.addr}"
                )
            else:
                logger.info(f"Socket exception in IPTransport to {self.addr}")
            return False

        if self._sock in readable:
            remote, remote_addr = self._sock.accept()
            handler = NotificationTransport(self.name, remote, remote_addr)
            self._add_sub_connection(handler)
            logger.debug(f"Accepted notification channel from {remote_addr}")

        return True

    def close(self):
        super().close()

    def broadcast(self, message: bytes) -> None:
        self._broadcast_sub_connections(message)
