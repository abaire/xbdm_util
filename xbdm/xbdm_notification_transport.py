from __future__ import annotations

import logging
import socket
from typing import Callable
from typing import Optional
from typing import Tuple

from net import ip_transport

logger = logging.getLogger(__name__)


class XBDMNotificationTransport(ip_transport.IPTransport):
    """Takes ownership of a socket and reads it in notification mode."""

    TERMINATOR = b"\r\n"

    def __init__(
        self,
        name: str,
        sock: socket.socket,
        addr: Tuple[str, int],
        read_buffer: Optional[bytearray] = None,
        handler: Callable[[str], None] = None,
    ):
        super().__init__(self._process_notification_data, f"! {name}")

        # Take over the socket from the existing transport.
        self._sock = sock
        self.addr = addr
        if read_buffer is not None:
            self._read_buffer = read_buffer
        if handler:
            self._handler = handler
        else:
            self._handler = self._default_handler

    def _process_notification_data(self, transport: ip_transport.IPTransport):
        terminator_len = len(self.TERMINATOR)
        terminator = transport.read_buffer.find(self.TERMINATOR)
        while terminator >= 0:
            message = transport.read_buffer[:terminator]
            self._handler(message.decode("utf-8"))

            transport.shift_read_buffer(terminator + terminator_len)
            terminator = transport.read_buffer.find(self.TERMINATOR)

    def _default_handler(self, message: str):
        logger.debug(f"{self.name}: {message}")
