from __future__ import annotations

import logging
import socket
from typing import Callable
from typing import Optional
from typing import Tuple

from . import ip_transport
from . import xbdm_notification_transport

logger = logging.getLogger(__name__)


class XBDMNotificationServer(ip_transport.IPTransport):
    """Creates a listener that will accept XBDMNotificationTransport connections."""

    def __init__(
        self,
        addr: Tuple[str, int],
        name: Optional[str] = None,
        handler: Callable[[str], None] = None,
    ):
        super().__init__(None, name)

        self._sock = socket.create_server(addr, backlog=1)
        self.addr = self._sock.getsockname()
        self._handler = handler

        if not name:
            self.name = f"{self.__class__.__name__}@{self.addr[1]}"

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
            transport = xbdm_notification_transport.XBDMNotificationTransport(
                self.name, remote, remote_addr, handler=self._handler
            )
            self._add_sub_connection(transport)
            logger.debug(f"Accepted notification channel from {remote_addr}")

        return True

    def close(self):
        super().close()

    def broadcast(self, message: bytes) -> None:
        logger.debug(f"Broadcasting: {message.decode('utf-8')}")
        self._broadcast_sub_connections(message)
