import socket
from typing import Optional


class IPTransport:
    """Models low level bidirectional socket transport."""

    def __init__(self, process_callback, name=""):
        self.name = name
        self._sock: Optional[socket.socket] = None
        self.addr: (str, int) = None
        self._read_buffer = bytearray()
        self._write_buffer = bytearray()
        self._on_bytes_read = process_callback

    @property
    def connected(self) -> bool:
        return self._sock is not None

    @property
    def read_buffer(self) -> bytearray:
        return self._read_buffer

    def shift_read_buffer(self, size):
        self._read_buffer = self._read_buffer[size:]

    def set_connection(self, sock, addr):
        self._sock = sock
        self.addr = addr

    def select(self, readable, writable, exceptional):
        if not self._sock:
            return

        readable.append(self._sock)
        exceptional.append(self._sock)
        if self._write_buffer:
            writable.append(self._sock)

    def close(self):
        if not self._sock:
            return
        if self.name:
            print(f"Closing connection {self.name} to {self.addr}")
        else:
            print(f"Closing connection to {self.addr}")
        self._sock.close()
        self._sock = None
        self.addr = None

    def send(self, buffer):
        self._write_buffer.extend(buffer)

    def process(
        self,
        readable: [socket.socket],
        writable: [socket.socket],
        exceptional: [socket.socket],
    ) -> bool:
        if not self._sock:
            return True

        if self._sock in exceptional:
            if self.name:
                print(f"Socket exception in IPTransport {self.name} to {self.addr}")
            else:
                print(f"Socket exception in IPTransport to {self.addr}")
            return False

        if self._sock in readable:
            data = self._sock.recv(4096)
            if not data:
                if self.name:
                    print(f"Remote closed in IPTransport {self.name} to {self.addr}")
                else:
                    print(f"Remote closed in IPTransport to {self.addr}")
                self.close()
                return False

            self._read_buffer.extend(data)
            if self._on_bytes_read:
                self._on_bytes_read(self)

        if self._sock in writable:
            bytes_sent = self._sock.send(self._write_buffer)
            self._write_buffer = self._write_buffer[bytes_sent:]

        return True
