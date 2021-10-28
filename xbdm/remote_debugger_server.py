"""Manages a socket to accept remote bridges to an XBDM."""
from __future__ import annotations

import logging
import select
import socket
import threading
import time
from typing import Callable
from typing import Optional
from typing import Set
from typing import Tuple

from net import ip_transport

logger = logging.getLogger(__name__)


class RemoteDebuggerServer(ip_transport.IPTransport):
    """Creates a listener that will accept IPTransport connections for bridging."""

    THREAD_SLEEP_SECS = 0.100

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

        self._client_lock = threading.RLock()
        self._new_clients = set()
        self._clients = set()

        # Clients are executed in a subthread to allow them to block on the XBDM
        # connection without deadlocking.
        self._running = True
        self._client_thread = threading.Thread(
            target=self._thread_main, name="XBDMBridgeClients"
        )
        self._client_thread.start()

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

            with self._client_lock:
                self._new_clients.add(transport)
            logger.debug(
                f"Accepted bridge channel to {self.xbdm_info} from {remote_addr}"
            )

        return True

    def close(self):
        self._running = False
        self._client_thread.join()

        for client in self._new_clients:
            client.close()
        for client in self._clients:
            client.close()

        super().close()

        self._new_clients.clear()
        self._clients.clear()

    def _thread_main(self):
        """Processes data from any connected bridge clients."""
        while self._running:
            with self._client_lock:
                new_clients: Set[ip_transport.IPTransport] = self._new_clients
                clients: Set[ip_transport.IPTransport] = self._clients

            # Start any new clients
            self._process_new_clients(new_clients)
            self._process_clients(clients)

    def _process_new_clients(self, new_clients: Set[ip_transport.IPTransport]):
        failed = set()
        for new_client in new_clients:
            if not new_client.start():
                failed.add(new_client)
                new_client.close()

        new_clients -= failed

        with self._client_lock:
            self._clients.update(new_clients)
            self._new_clients.clear()

    def _process_clients(self, clients: Set[ip_transport.IPTransport]):
        if not clients:
            time.sleep(self.THREAD_SLEEP_SECS)
            return

        readable = []
        writable = []
        exceptional = []

        for client in clients:
            client.select(readable, writable, exceptional)

        readable, writable, exceptional = select.select(
            readable, writable, exceptional, self.THREAD_SLEEP_SECS
        )

        closed_channels = set()
        for connection in clients:
            if not connection.process(readable, writable, exceptional):
                closed_channels.add(connection)

        with self._client_lock:
            self._clients -= closed_channels
