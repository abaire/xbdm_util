"""Manages a transport interface to an XBDM."""
import logging
import select
import socket
import time
import threading
from typing import Callable
from typing import Optional
from typing import Tuple

from . import ip_transport
from . import rdcp_command
from . import xbdm_transport

SELECT_TIMEOUT_SECS = 0.25
logger = logging.getLogger(__name__)


class XBDMConnection:
    """Manages an XBDM connection."""

    def __init__(self, listen_ip: str, xbox_name: str, xbox_addr: Tuple[str, int]):
        self.listen_ip = listen_ip
        self.xbox_name = xbox_name
        self.xbox_addr = xbox_addr

        self._xbdm: Optional[xbdm_transport.XBDMTransport] = None

        self._listen_sock: Optional[socket.socket] = None
        self.listen_addr: Optional[Tuple[str, int]] = None
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

    def reconnect(self):
        self.shutdown()
        logger.info("Reconnecting...")
        self._startup()

    def _startup(self):
        self._listen_sock = socket.create_server((self.listen_ip, 0), backlog=1)
        self.listen_addr = self._listen_sock.getsockname()
        logger.info(
            f"Bridging connections to {self.xbox_info} at port {self.listen_addr[1]}"
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

    def send_rdcp_command(self, cmd: rdcp_command.RDCPCommand) -> bool:
        return self._xbdm.send_command(cmd)

    def create_notification_listener(self, port: int):
        self._xbdm.create_notification_server(port)

    def _thread_main(self):
        try:
            while self._running:
                readable = [self._listen_sock]
                writable = []
                exceptional = [self._listen_sock]

                self._xbdm.select(readable, writable, exceptional)

                readable, writable, exceptional = select.select(
                    readable, writable, exceptional, SELECT_TIMEOUT_SECS
                )

                if not self._xbdm.process(readable, writable, exceptional):
                    self._running = False
                    break

        except ConnectionResetError:
            self._running = False

        logger.debug(f"Shutting down connection for {self.xbox_info}")
        self._close()

    def await_empty_queue(self) -> None:
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

        logger.info(f"Connected to XBDM {self.xbox_info}")
        sock.setblocking(False)
        self._xbdm.set_connection(sock, self.xbox_addr)
        return True
