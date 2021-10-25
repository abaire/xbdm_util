"""Manages a socket to accept remote bridges to an XBDM."""
from __future__ import annotations

import logging
import socket
from typing import Callable
from typing import Optional
from typing import Tuple

from net import ip_transport

logger = logging.getLogger(__name__)


class XBDMBridgeRemoteServer(ip_transport.IPTransport):
    """Creates a listener that will accept IPTransport connections for bridging."""

    def __init__(
        self,
        xbdm_info: str,
        addr: Tuple[str, int],
        handler: Callable[
            [socket.socket, Tuple[str, int]], Optional[ip_transport.IPTransport]
        ],
    ):
        super().__init__(None, "")

        self._sock = socket.create_server(addr, backlog=1)
        self._handler = handler

        self.xbdm_info = xbdm_info
        self.addr = self._sock.getsockname()
        self.name = f"{self.__class__.__name__}@{self.addr[1]} => {self.xbdm_info}"

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
            transport = self._handler(remote, remote_addr)
            if not transport:
                remote.shutdown(socket.SHUT_RDWR)
                remote.close()
                return True

            self._add_sub_connection(transport)
            logger.debug(
                f"Accepted bridge channel to {self.xbdm_info} from {remote_addr}"
            )

        return True

    def close(self):
        super().close()
