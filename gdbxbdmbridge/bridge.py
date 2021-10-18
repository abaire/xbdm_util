"""Provides bridging between GDB and XBDM."""
import logging
import select
import socket
import time
import threading
from typing import Callable

from . import ip_transport
from . import rdcp_command
from . import xbdm_transport

SELECT_TIMEOUT_SECS = 0.25
logger = logging.getLogger(__name__)


class GDBXBDMBridge:
    """Bridges GDB and XBDM protocols."""

    def __init__(self, listen_ip, xbox_name, xbox_addr):
        self.listen_ip = listen_ip
        self.xbox_name = xbox_name
        self.xbox_addr = xbox_addr

        self._listen_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._listen_sock.bind((self.listen_ip, 0))
        self._listen_sock.listen(1)
        self.listen_addr = self._listen_sock.getsockname()
        logger.info(
            f"Bridging connections to {self.xbox_info} at port {self.listen_addr[1]}"
        )

        self._gdb = ip_transport.IPTransport(
            lambda transport: self._process_gdb_data(transport), "GDB"
        )
        self._xbdm = xbdm_transport.XBDMTransport("XBDM")

        self._running = True
        self._thread = threading.Thread(
            target=lambda bridge: bridge._thread_main(),
            name=f"Bridge {self.xbox_info}",
            args=(self,),
        )
        self._thread.start()

    def shutdown(self):
        self._running = False
        self._thread.join()
        self._close()

    @property
    def xbox_info(self) -> str:
        return f"{self.xbox_name}@{self.xbox_addr[0]}:{self.xbox_addr[1]}"

    @property
    def can_process_xbdm_commands(self) -> bool:
        return self._xbdm.can_process_commands

    def _close(self):
        self._running = False
        self._close_listen_socket()

        if self._gdb:
            self._gdb.close()

        if self._xbdm:
            self._xbdm.close()

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

    def _thread_main(self):
        while self._running:
            readable = [self._listen_sock]
            writable = []
            exceptional = [self._listen_sock]

            self._gdb.select(readable, writable, exceptional)
            self._xbdm.select(readable, writable, exceptional)

            readable, writable, exceptional = select.select(
                readable, writable, exceptional, SELECT_TIMEOUT_SECS
            )

            if not self._gdb.process(readable, writable, exceptional):
                self._close()
                self.shutdown()
                return

            if not self._xbdm.process(readable, writable, exceptional):
                self._close()
                self.shutdown()
                return

            if self._listen_sock in readable and not self._accept_gdb_connection():
                break

    def _accept_gdb_connection(self):
        remote, remote_addr = self._listen_sock.accept()

        if self._gdb.connected:
            logger.warning(
                f"Denying GDB connection from {remote_addr} as socket is already connected."
            )
            remote.close()
            return True

        logger.info(f"Accepted GDB connection from {remote_addr}")
        remote.setblocking(False)

        self._gdb.set_connection(remote, remote_addr)

        if not self._connect_to_xbdm():
            self._close()
            return False
        return True

    def _close_listen_socket(self):
        logger.info(f"Closing GDB bridge to {self.xbox_info} at {self.listen_addr[1]}")
        self._listen_sock.close()

    def _connect_to_xbdm(self) -> bool:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        logger.info(f"Connecting to XBDM {self.xbox_addr}")
        try:
            sock.connect(self.xbox_addr)
        except ConnectionRefusedError:
            logger.error(f"Failed to connect to XBDM {self.xbox_info}")
            return False

        logger.info(f"Connected to XBDM {self.xbox_info}")
        sock.setblocking(False)
        self._xbdm.set_connection(sock, self.xbox_addr)
        return True

    def _process_gdb_data(self, transport: ip_transport.IPTransport):
        pass

    def send_rdcp_command(self, cmd: rdcp_command.RDCPCommand) -> bool:
        return self._xbdm.send_command(cmd)
