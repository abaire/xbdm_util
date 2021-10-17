"""Provides bridging between GDB and XBDM."""
import select
import socket
import threading
import time

from . import rdcp_command


class GDBXBDMBridge:
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

        self._gdb_thread = threading.Thread(
            target=lambda bridge: bridge._gdb_thread_main(),
            name=f"GDB Thread {self.xbox_info}",
            args=(self,),
        )
        self._gdb_sock = None
        self._gdb_addr = None

        self._xbdm_thread = threading.Thread(
            target=lambda bridge: bridge._xbdm_thread_main(),
            name=f"XBDM Thread {self.xbox_info}",
            args=(self,),
        )
        self._xbdm_sock = None
        self._xbdm_addr = None
        self._xbdm_read_buffer = bytearray()
        self._xbdm_write_buffer = bytearray()

        self._running = True
        self._gdb_thread.start()

    def shutdown(self):
        self._running = False

    @property
    def xbox_info(self):
        return f"{self.xbox_name}@{self.xbox_addr[0]}:{self.xbox_addr[1]}"

    def close(self):
        self._close_gdb_bridge()
        self._close_xbdm_bridge()

    def _gdb_thread_main(self):
        remote, remote_addr = self._listen_sock.accept()
        print(f"Accepted GDB connection from {remote_addr}")

        self._gdb_sock = remote
        self._gdb_addr = remote_addr

        self._xbdm_thread.start()

        # TODO: Loop and receive commands from the GDB stub until connection is closed.
        time.sleep(120)
        self._close_gdb_bridge()

    def _close_gdb_bridge(self):
        print(f"Closing GDB bridge to {self.xbox_info} at {self._listen_addr[1]}")
        if self._gdb_sock:
            self._gdb_sock.close()
        self._listen_sock.close()

    def _xbdm_thread_main(self):
        self._xbdm_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        print(f"Connecting to XBDM {self.xbox_addr}")
        try:
            self._xbdm_sock.connect(self.xbox_addr)
        except ConnectionRefusedError:
            print(f"Failed to connect to XBDM {self.xbox_info}")
            return

        print(f"Connected to XBDM {self.xbox_info}")

        self._xbdm_sock.setblocking(False)

        while self._running:
            readable = [self._xbdm_sock]
            writable = [self._xbdm_sock] if self._xbdm_write_buffer else []
            exceptional = [self._xbdm_sock]

            readable, writable, exceptional = select.select(
                readable, writable, exceptional, 0.25
            )
            if self._xbdm_sock in readable:
                data = self._xbdm_sock.recv(4096)
                if not data:
                    self.close()
                    break

                self._xbdm_read_buffer.extend(data)
                self._process_xbdm_data()

            if self._xbdm_sock in writable:
                bytes_sent = self._xbdm_sock.send(self._xbdm_write_buffer)
                self._xbdm_write_buffer = self._xbdm_write_buffer[bytes_sent:]

        # self._xbdm_sock.sendall("systime\r\n")

        time.sleep(90)
        self._close_xbdm_bridge()

    def _process_xbdm_data(self):
        cmd = rdcp_command.RDCPCommand()

        bytes_procesed = cmd.parse(self._xbdm_read_buffer)
        while bytes_procesed > 0:
            # TODO: Handle the processed command.
            self._xbdm_read_buffer = self._xbdm_read_buffer[bytes_procesed:]
            bytes_procesed = cmd.parse(self._xbdm_read_buffer)

        print(f"After processing: {self._xbdm_read_buffer}")

    def _close_xbdm_bridge(self):
        if not self._xbdm_sock:
            return
        print(f"Closing XBDM connection to {self.xbox_info}")
        self._xbdm_sock.close()
