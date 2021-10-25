"""Provides a GDB<->XBDM bridge.

See https://sourceware.org/gdb/onlinedocs/gdb/Remote-Protocol.html
See https://www.embecosm.com/appnotes/ean4/embecosm-howto-rsp-server-ean4-issue-2.html
"""

from __future__ import annotations

import collections
import logging
import socket
from typing import Callable
from typing import Dict
from typing import List
from typing import Optional
from typing import Tuple

from . import packet
from xbdm import ip_transport
from xbdm import xbdm_transport

logger = logging.getLogger(__name__)


class GDBTransport(ip_transport.IPTransport):
    """GDB Remote Serial Protocol translation of XDBM functions."""

    def __init__(self, xbdm: xbdm_transport.XBDMTransport):
        super().__init__(process_callback=self._on_bytes_read)
        self._xbdm = xbdm
        self._send_queue = collections.deque()

        self.features = {"QStartNoAckMode": False}

    @property
    def has_buffered_data(self) -> bool:
        # TODO: Make this thread safe.
        return self._send_queue or self._read_buffer or self._write_buffer

    def send_packet(self, p: packet.GDBPacket):
        self._send_queue.append(p)
        self._send_next_packet()

    def _send_next_packet(self):
        if not self._send_queue:
            return

        p: packet.GDBPacket = self._send_queue.popleft()
        data = p.serialize()
        logger.debug(f"Sending GDB packet: {data.decode('utf-8')}")
        self.send(data)

    def _recv(self, data: bytes):
        # RSP uses '}' as an escape character. Escapes are processed in this method
        # before adding to the read buffer to simplify parsing.

        if not data:
            return

        # Process any left over escapes.
        if (
            self._read_buffer
            and self._read_buffer[-1] == packet.GDBPacket.RSP_ESCAPE_CHAR
        ):
            self._read_buffer[-1] = data[0] ^ 0x20
            data = data[1:]

        escape_char_index = data.find(packet.GDBPacket.RSP_ESCAPE_CHAR)
        while escape_char_index >= 0:
            if escape_char_index == len(data):
                # If there are no more characters after the escape char, just add it to the buffer and let it be
                # processed when more data is received.
                break

            if escape_char_index:
                self._read_buffer.extend(data[: escape_char_index - 1])

            unescaped = data[escape_char_index + 1] ^ 0x20
            self._read_buffer.append(unescaped)
            data = data[escape_char_index + 2 :]

        self._read_buffer.extend(data)

    def _on_bytes_read(self, _ignored):
        p = packet.GDBPacket()

        while self._read_buffer:
            if self._read_buffer[0] == ord("+"):
                self.shift_read_buffer(1)
                continue

            if self._read_buffer[0] == ord("-"):
                # TODO: Handle - acks.
                self.shift_read_buffer(1)
                continue

            if self._read_buffer[0] == 0x03:
                # TODO: Handle interrupt requests.
                logger.warning("Skipping unsupported interrupt request")
                self.shift_read_buffer(1)
                continue

            leader = self._read_buffer.find(packet.GDBPacket.PACKET_LEADER)
            if leader > 0:
                logger.warning(
                    f"Skipping {leader} non-leader bytes {self._read_buffer[:leader].hex()}"
                )

            bytes_consumed = p.parse(self._read_buffer)
            if not bytes_consumed:
                break
            self.shift_read_buffer(bytes_consumed)
            logger.debug(
                f"After processing: [{len(self._read_buffer)}] {self._read_buffer.hex()}"
            )

            if p.checksum_ok:
                if not self.features["QStartNoAckMode"]:
                    self.send(b"+")
                self._process_packet(p)
            elif not self.features["QStartNoAckMode"]:
                self.send(b"-")

    def _process_packet(self, p: packet.GDBPacket):
        if p.data.startswith("qSupported"):
            self._handle_supported_query(p)
            return

        if p.data == "vMustReplyEmpty":
            self._handle_vMustReplyEmpty(p)
            return

        if p.data == "QStartNoAckMode":
            self._handle_QStartNoAckMode(p)
            return

        if p.data == "qTStatus":
            self._handle_query_trace_status(p)
            return

        logger.warning(f"Unsupported GDB packet {p}")

    def _handle_supported_query(self, p: packet.GDBPacket):
        request = p.data.split(":", 1)
        if len(request) != 2:
            logger.error(f"Unsupported qSupported message {p.data}")
            return

        response = []
        features = request[1].split(";")
        for feature in features:
            if feature == "multiprocess+":
                # Do not support multiprocess extensions.
                response.append("multiprocess-")
                continue
            if feature == "swbreak+":
                self.features["swbreak"] = True
                response.append("swbreak+")
                continue
            if feature == "hwbreak+":
                self.features["hwbreak"] = True
                response.append("hwbreak+")
                continue
            if feature == "qRelocInsn+":
                response.append("qRelocInsn-")
                continue
            if feature == "fork-events+":
                response.append("fork-events-")
                continue
            if feature == "vfork-events+":
                response.append("vfork-events-")
                continue
            if feature == "exec-events+":
                response.append("exec-events-")
                continue
            if feature == "vContSupported+":
                response.append("vContSupported-")
                continue
            if feature == "QThreadEvents+":
                response.append("QThreadEvents-")
                continue
            if feature == "no-resumed+":
                response.append("no-resumed-")
                continue
            if feature == "xmlRegisters=i386":
                self.features["xmlRegisters"] = "i386"
                continue

        response.append("QStartNoAckMode+")

        p = packet.GDBPacket(";".join(response))
        self.send_packet(p)

    def _handle_vMustReplyEmpty(self, _p: packet.GDBPacket):
        self.send_packet(packet.GDBPacket())

    def _handle_QStartNoAckMode(self, _p: packet.GDBPacket):
        self.features["QStartNoAckMode+"] = True
        self.send_packet(packet.GDBPacket("OK"))

    def _handle_query_trace_status(self, _p: packet.GDBPacket):
        self.send_packet(packet.GDBPacket(""))


def _handle_build_command(
    _args: List[str],
) -> Optional[
    Callable[
        [xbdm_transport.XBDMTransport, socket.socket, Tuple[str, int]],
        Optional[ip_transport.IPTransport],
    ]
]:
    def construct_transport(
        xbdm: xbdm_transport.XBDMTransport,
        remote: socket.socket,
        remote_addr: Tuple[str, int],
    ) -> Optional[ip_transport.IPTransport]:
        ret = GDBTransport(xbdm)
        ret.set_connection(remote, remote_addr)
        return ret

    return construct_transport
