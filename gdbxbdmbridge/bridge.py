"""Provides bridging between GDB and XBDM."""
import select
import socket
import threading

from . import ip_transport
from . import rdcp_command

SELECT_TIMEOUT_SECS = 0.25


class GDBXBDMBridge:
    """Bridges GDB and XBDM protocols."""

    STATE_INIT = 0
    STATE_CONNECTED = 1

    def __init__(self, listen_ip, xbox_name, xbox_addr):
        self.listen_ip = listen_ip
        self.xbox_name = xbox_name
        self.xbox_addr = xbox_addr

        self._listen_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._listen_sock.bind((self.listen_ip, 0))
        self._listen_sock.listen(1)
        self._listen_addr = self._listen_sock.getsockname()
        print(
            f"Bridging connections to {self.xbox_info} at port {self._listen_addr[1]}"
        )

        self._gdb = ip_transport.IPTransport(
            lambda transport: self._process_gdb_data(transport),
            "GDB"
        )
        self._xbdm = ip_transport.IPTransport(
            lambda transport: self._process_xbdm_data(transport),
            "XBDM"
        )

        self._xbdm_state = self.STATE_INIT

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
    def xbox_info(self):
        return f"{self.xbox_name}@{self.xbox_addr[0]}:{self.xbox_addr[1]}"

    def _close(self):
        self._running = False
        self._close_listen_socket()

        if self._gdb:
            self._gdb.close()

        if self._xbdm:
            self._xbdm.close()

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
            print(
                f"Denying GDB connection from {remote_addr} as socket is already connected."
            )
            remote.close()
            return True

        print(f"Accepted GDB connection from {remote_addr}")
        remote.setblocking(False)

        self._gdb.set_connection(remote, remote_addr)

        if not self._connect_to_xbdm():
            self._close()
            return False
        return True

    def _close_listen_socket(self):
        print(f"Closing GDB bridge to {self.xbox_info} at {self._listen_addr[1]}")
        self._listen_sock.close()

    def _connect_to_xbdm(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        print(f"Connecting to XBDM {self.xbox_addr}")
        try:
            sock.connect(self.xbox_addr)
        except ConnectionRefusedError:
            print(f"Failed to connect to XBDM {self.xbox_info}")
            return False

        print(f"Connected to XBDM {self.xbox_info}")
        sock.setblocking(False)
        self._xbdm.set_connection(sock, self.xbox_addr)
        return True

    def _process_gdb_data(self, transport: ip_transport.IPTransport):
        pass

    def _process_xbdm_data(self, transport: ip_transport.IPTransport):
        cmd = rdcp_command.RDCPCommand()

        bytes_procesed = cmd.parse(transport.read_buffer)
        while bytes_procesed > 0:
            if not self._process_rdcp_command(cmd):
                break
            transport.shift_read_buffer(bytes_procesed)
            bytes_procesed = cmd.parse(transport.read_buffer)

        print(f"After processing: {transport.read_buffer}")

    def _process_rdcp_command(self, cmd: rdcp_command.RDCPCommand) -> bool:
        print(f"Processing RDCP command {cmd}")
        if self._xbdm_state == self.STATE_INIT:
            if cmd.status != cmd.STATUS_OK and cmd.status != cmd.STATUS_CONNECTED:
                return False
            self._xbdm_state = self.STATE_CONNECTED
            return True

        return True
