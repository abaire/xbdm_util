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
from typing import Mapping
from typing import Optional
from typing import Tuple

from . import resources
from .packet import GDBPacket
from .packet import GDBBinaryPacket
from net import ip_transport
from xbdm import debugger
from xbdm import xbdm_bridge

logger = logging.getLogger(__name__)


class GDBTransport(ip_transport.IPTransport):
    """GDB Remote Serial Protocol translation of XDBM functions."""

    # Indicates that a request should apply to all threads.
    TID_ALL_THREADS = -1
    # Indicates that a request should apply to any arbitrary thread.
    TID_ANY_THREAD = 0

    ERR_RETRIEVAL_FAILED = 0xD0

    ORDERED_REGISTERS = [
        "Ebp",
        "Esp",
        "Eip",
        "EFlags",
        "Eax",
        "Ebx",
        "Ecx",
        "Edx",
        "Esi",
        "Edi",
        "Cr0NpxState",
        "ST0",
        "ST1",
        "ST2",
        "ST3",
        "ST4",
        "ST5",
        "ST6",
        "ST7",
    ]

    REGISTER_FORMATTERS = {
        "Ebp": r"%08x",
        "Esp": r"%08x",
        "Eip": r"%08x",
        "EFlags": r"%08x",
        "Eax": r"%08x",
        "Ebx": r"%08x",
        "Ecx": r"%08x",
        "Edx": r"%08x",
        "Esi": r"%08x",
        "Edi": r"%08x",
        "Cr0NpxState": r"%08x",
        "ST0": r"%020x",
        "ST1": r"%020x",
        "ST2": r"%020x",
        "ST3": r"%020x",
        "ST4": r"%020x",
        "ST5": r"%020x",
        "ST6": r"%020x",
        "ST7": r"%020x",
    }

    def __init__(self, bridge: xbdm_bridge.XBDMBridge, name: str):
        super().__init__(process_callback=self._on_bytes_read, name=name)
        self._bridge: xbdm_bridge.XBDMBridge = bridge
        self._debugger: Optional[debugger.Debugger] = None
        self._send_queue = collections.deque()

        # Maps a command type to the thread id that should be used when interpreting that command.
        self._command_thread_id_context: Dict[str, int] = {}

        self.features = {"QStartNoAckMode": False}
        self._dispatch_table: Mapping[
            str, Callable[[GDBPacket], None]
        ] = self._build_dispatch_table(self)

        self._thread_info_buffer: List[int] = []

    def start(self):
        self._debugger = debugger.Debugger(self._bridge)
        self._debugger.attach()
        self._debugger.halt()

        thread = self._debugger.active_thread
        if not thread:
            return

        self._send_thread_stop_packet(thread)

    def close(self):
        if self._debugger:
            self._debugger.shutdown()
            self._debugger = None

        super().close()

    @property
    def has_buffered_data(self) -> bool:
        # TODO: Make this thread safe.
        return self._send_queue or self._read_buffer or self._write_buffer

    def send_packet(self, pkt: GDBPacket):
        self._send_queue.append(pkt)
        self._send_next_packet()

    def _send_next_packet(self):
        if not self._send_queue:
            return

        pkt: GDBPacket = self._send_queue.popleft()
        data = pkt.serialize()
        logger.debug(f"Sending GDB packet: {data.decode('utf-8')}")
        self.send(data)

    def _recv(self, data: bytes):
        # RSP uses '}' as an escape character. Escapes are processed in this method
        # before adding to the read buffer to simplify parsing.

        if not data:
            return

        # Process any left over escapes.
        if self._read_buffer and self._read_buffer[-1] == GDBPacket.RSP_ESCAPE_CHAR:
            self._read_buffer[-1] = data[0] ^ 0x20
            data = data[1:]

        escape_char_index = data.find(GDBPacket.RSP_ESCAPE_CHAR)
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
        pkt = GDBPacket()

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

            leader = self._read_buffer.find(GDBPacket.PACKET_LEADER)
            if leader > 0:
                logger.warning(
                    f"Skipping {leader} non-leader bytes {self._read_buffer[:leader].hex()}"
                )

            bytes_consumed = pkt.parse(self._read_buffer)
            if not bytes_consumed:
                break
            self.shift_read_buffer(bytes_consumed)

            logger.debug(f"Processed packet {pkt}")
            # logger.debug(
            #     f"After processing: [{len(self._read_buffer)}] {self._read_buffer.hex()}"
            # )

            if pkt.checksum_ok:
                if not self.features["QStartNoAckMode"]:
                    self.send(b"+")
                self._process_packet(pkt)
            elif not self.features["QStartNoAckMode"]:
                self.send(b"-")

    def _process_packet(self, pkt: GDBPacket):
        """Dispatches the given packet to the appropriate handler."""
        if len(pkt.data) > 1:
            command_id = pkt.data[:2]
            handler = self._dispatch_table.get(command_id)
            if handler:
                handler(pkt)
                return

        if pkt.data:
            command_id = pkt.data[0]
            handler = self._dispatch_table.get(command_id)
            if handler:
                handler(pkt)
                return

        logger.warning(f"Unsupported GDB packet {pkt}")

    @staticmethod
    def _build_dispatch_table(target) -> Mapping[str, Callable[[GDBPacket], None]]:
        """Populates _dispatch_table with handler callables."""
        return {
            "!": target._handle_enable_extended_mode,
            "?": target._handle_query_halt_reason,
            "A": target._handle_argv,
            "b": target._handle_deprecated_command,
            "B": target._handle_deprecated_command,
            "bc": target._handle_backward_continue,
            "bs": target._handle_backward_step,
            "c": target._handle_continue,
            "C": target._handle_continue_with_signal,
            "d": target._handle_deprecated_command,
            "D": target._handle_detach,
            "F": target._handle_file_io,
            "g": target._handle_read_general_registers,
            "G": target._handle_write_general_registers,
            "H": target._handle_select_thread_for_command_group,
            "i": target._handle_step_instruction,
            "I": target._handle_signal_step,
            "k": target._handle_kill,
            "m": target._handle_read_memory,
            "M": target._handle_write_memory,
            "p": target._handle_read_register,
            "P": target._handle_write_register,
            "q": target._handle_read_query,
            "Q": target._handle_write_query,
            "r": target._handle_deprecated_command,
            "R": target._handle_restart_system,
            "s": target._handle_single_step,
            "S": target._handle_single_step_with_signal,
            "t": target._handle_search_backward,
            "T": target._handle_check_thread_alive,
            "v": target._handle_extended_v_command,
            "X": target._handle_write_memory_binary,
            "z": target._handle_insert_breakpoint_type,
            "Z": target._handle_remove_breakpoint_type,
        }

    def _handle_enable_extended_mode(self, pkt: GDBPacket):
        logger.error(f"Unsupported packet {pkt.data}")
        self.send_packet(GDBPacket())

    def _handle_query_halt_reason(self, pkt: GDBPacket):
        thread = self._debugger.active_thread
        if not thread or not thread.fetch_stop_reason():
            logger.error("Halt query issued but target is not halted.")
            self.send_packet(GDBPacket())
            return
        self._send_thread_stop_packet(thread)

    def _handle_argv(self, pkt: GDBPacket):
        logger.error(f"Unsupported packet {pkt.data}")
        self.send_packet(GDBPacket())

    def _handle_backward_continue(self, pkt: GDBPacket):
        logger.error(f"Unsupported packet {pkt.data}")
        self.send_packet(GDBPacket())

    def _handle_backward_step(self, pkt: GDBPacket):
        logger.error(f"Unsupported packet {pkt.data}")
        self.send_packet(GDBPacket())

    def _handle_continue(self, pkt: GDBPacket):
        logger.error(f"Unsupported packet {pkt.data}")
        self.send_packet(GDBPacket())

    def _handle_continue_with_signal(self, pkt: GDBPacket):
        logger.error(f"Unsupported packet {pkt.data}")
        self.send_packet(GDBPacket())

    def _handle_deprecated_command(self, pkt: GDBPacket):
        logger.debug(f"Ignoring deprecated command: {pkt.data}")
        self.send_packet(GDBPacket())

    def _handle_detach(self, pkt: GDBPacket):
        logger.error(f"Unsupported packet {pkt.data}")
        self.send_packet(GDBPacket())

    def _handle_file_io(self, pkt: GDBPacket):
        logger.error(f"Unsupported packet {pkt.data}")
        self.send_packet(GDBPacket())

    def _handle_read_general_registers(self, pkt: GDBPacket):
        thread_id = self._command_thread_id_context.get("g", None)
        if thread_id is None:
            logger.warning("Received 'g' command but no thread set! Treating as ANY.")
            thread_id = self.TID_ANY_THREAD

        if thread_id == self.TID_ALL_THREADS:
            logger.error(f"Unsupported 'g' query for all threads.")
            self._send_empty()
            return

        if thread_id == self.TID_ANY_THREAD:
            thread_id = self._debugger.any_thread_id

        thread = self._debugger.get_thread(thread_id)

        context: debugger.Thread.FullContext = thread.get_full_context()
        if not context:
            self._send_error(self.ERR_RETRIEVAL_FAILED)

        body = []
        for register in self.ORDERED_REGISTERS:
            value: Optional[int] = context.registers.get(register, None)
            fmt = self.REGISTER_FORMATTERS[register]
            if value is None:
                dummy = fmt % 0
                str_value = "?" * len(dummy)
            else:
                str_value = fmt % value

            # logger.debug(f"{register}: {str_value}")
            body.append(str_value)

        self.send_packet(GDBPacket("".join(body)))

    def _handle_write_general_registers(self, pkt: GDBPacket):
        logger.error(f"Unsupported packet {pkt.data}")
        self.send_packet(GDBPacket())

    def _handle_select_thread_for_command_group(self, pkt: GDBPacket):
        if len(pkt.data) < 3:
            logger.error(f"Command missing parameters: {pkt.data}")
            self.send_packet(GDBPacket("E"))
            return

        op = pkt.data[1]
        thread_id = int(pkt.data[2:], 16)
        self._command_thread_id_context[op] = thread_id
        self.send_packet(GDBPacket("OK"))

    def _handle_step_instruction(self, pkt: GDBPacket):
        logger.error(f"Unsupported packet {pkt.data}")
        self.send_packet(GDBPacket())

    def _handle_signal_step(self, pkt: GDBPacket):
        logger.error(f"Unsupported packet {pkt.data}")
        self.send_packet(GDBPacket())

    def _handle_kill(self, pkt: GDBPacket):
        logger.error(f"Unsupported packet {pkt.data}")
        self.send_packet(GDBPacket())

    def _handle_read_memory(self, pkt: GDBPacket):
        logger.error(f"Unsupported packet {pkt.data}")
        self.send_packet(GDBPacket())

    def _handle_write_memory(self, pkt: GDBPacket):
        logger.error(f"Unsupported packet {pkt.data}")
        self.send_packet(GDBPacket())

    def _handle_read_register(self, pkt: GDBPacket):
        logger.error(f"Unsupported packet {pkt.data}")
        self.send_packet(GDBPacket())

    def _handle_write_register(self, pkt: GDBPacket):
        logger.error(f"Unsupported packet {pkt.data}")
        self.send_packet(GDBPacket())

    def _handle_read_query(self, pkt: GDBPacket):
        query = pkt.data[1:]

        if query.startswith("Attached"):
            self._handle_query_attached(pkt)
            return

        if query.startswith("Supported"):
            self._handle_query_supported(pkt)
            return

        if query == "fThreadInfo":
            self._handle_thread_info_start()
            return

        if query == "sThreadInfo":
            self._handle_thread_info_continue()
            return

        if query == "TStatus":
            self._handle_query_trace_status()
            return

        if query == "C":
            self._handle_query_current_thread_id()
            return

        if query.startswith("Xfer:features:read:"):
            self._handle_features_read(pkt)
            return

        logger.error(f"Unsupported query read packet {pkt.data}")
        self.send_packet(GDBPacket())

    def _handle_write_query(self, pkt: GDBPacket):
        if pkt.data == "QStartNoAckMode":
            self._start_no_ack_mode()
            return

        logger.error(f"Unsupported query write packet {pkt.data}")
        self.send_packet(GDBPacket())

    def _handle_restart_system(self, pkt: GDBPacket):
        logger.error(f"Unsupported packet {pkt.data}")
        self.send_packet(GDBPacket())

    def _handle_single_step(self, pkt: GDBPacket):
        logger.error(f"Unsupported packet {pkt.data}")
        self.send_packet(GDBPacket())

    def _handle_single_step_with_signal(self, pkt: GDBPacket):
        logger.error(f"Unsupported packet {pkt.data}")
        self.send_packet(GDBPacket())

    def _handle_search_backward(self, pkt: GDBPacket):
        logger.error(f"Unsupported packet {pkt.data}")
        self.send_packet(GDBPacket())

    def _handle_check_thread_alive(self, pkt: GDBPacket):
        logger.error(f"Unsupported packet {pkt.data}")
        self.send_packet(GDBPacket())

    def _handle_extended_v_command(self, pkt: GDBPacket):
        if pkt.data == "vMustReplyEmpty":
            self._send_empty()
            return

        logger.error(f"Unsupported v packet {pkt.data}")
        self.send_packet(GDBPacket())

    def _handle_write_memory_binary(self, pkt: GDBPacket):
        logger.error(f"Unsupported packet {pkt.data}")
        self.send_packet(GDBPacket())

    def _handle_insert_breakpoint_type(self, pkt: GDBPacket):
        logger.error(f"Unsupported packet {pkt.data}")
        self.send_packet(GDBPacket())

    def _handle_remove_breakpoint_type(self, pkt: GDBPacket):
        logger.error(f"Unsupported packet {pkt.data}")
        self.send_packet(GDBPacket())

    def _handle_query_attached(self, _pkt: GDBPacket):
        # If attached to an existing process:
        self.send_packet(GDBPacket("1"))
        # elif started new process
        # self.send_packet(GDBPacket("0"))

    def _handle_query_supported(self, pkt: GDBPacket):
        request = pkt.data.split(":", 1)
        if len(request) != 2:
            logger.error(f"Unsupported qSupported message {pkt.data}")
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
                # Registers are provided via qXfer:features
                continue

        # Disable acks.
        response.append("QStartNoAckMode+")

        # Instruct GDB to ask us for CPU features since only a subset of i386
        # information is retrievable from XBDM.
        response.append("qXfer:features:read+")

        pkt = GDBPacket(";".join(response))
        self.send_packet(pkt)

    def _handle_thread_info_start(self):
        self._thread_info_buffer = [thr.thread_id for thr in self._debugger.threads]

        if not self._thread_info_buffer:
            self.send_packet(GDBPacket("l"))
            return
        self._send_thread_info()

    def _handle_thread_info_continue(self):
        if not self._thread_info_buffer:
            self.send_packet(GDBPacket("l"))
            return
        self._send_thread_info()

    def _send_thread_info(self, send_all: bool = True):
        if send_all:
            threads = ",".join(["%x" % tid for tid in self._thread_info_buffer])
            self.send_packet(GDBPacket(f"m{threads}"))
            self._thread_info_buffer.clear()
            return

        self.send_packet(GDBPacket("m%x" % self._thread_info_buffer.pop()))

    def _handle_query_trace_status(self):
        # TODO: Actually support trace experiments.
        # GDBPacket("T0")
        self._send_empty()

    def _handle_query_current_thread_id(self):
        thread = self._debugger.active_thread
        if not thread:
            self._send_empty()

        self.send_packet(GDBPacket("QC%x" % thread.thread_id))

    def _handle_features_read(self, pkt: GDBPacket):
        target_file, region = pkt.data[pkt.data.index("read:") + 5 :].split(":")
        start, length = region.split(",")
        start = int(start, 16)
        length = int(length, 16)
        end = start + length

        body = resources.RESOURCES.get(target_file)
        if not body:
            self._send_error(0)
            return

        logger.debug(f"Read requested from {target_file} {start} - {end}")
        self._send_xfer_response(body, start, end)

    def _send_xfer_response(self, body: bytes, start: int, end: int):
        body_size = len(body)

        if start >= body_size:
            self.send_packet(GDBPacket("l"))
            return

        prefix = b"l" if end >= body_size else b"m"
        if end > body_size:
            end = body_size
        body = body[start:end]

        self.send_packet(GDBBinaryPacket(prefix + body))

    def _send_empty(self):
        self.send_packet(GDBPacket())

    def _send_error(self, error_number: int):
        self.send_packet(GDBPacket("E%02X" % error_number))

    def _send_thread_stop_packet(self, thread: debugger.Thread):
        halt_signal = thread.last_stop_reason_signal
        if not halt_signal:
            return False

        # TODO: send detailed information.
        # see https://sourceware.org/gdb/onlinedocs/gdb/Stop-Reply-Packets.html#Stop-Reply-Packets
        self.send_packet(GDBPacket("T%02xthread:%x;" % (halt_signal, thread.thread_id)))

        return True

    def _start_no_ack_mode(self):
        self.features["QStartNoAckMode+"] = True
        self.send_packet(GDBPacket("OK"))


def _handle_build_command(
    _args: List[str],
) -> Optional[
    Callable[
        [xbdm_bridge.XBDMBridge, socket.socket, Tuple[str, int]],
        Optional[ip_transport.IPTransport],
    ]
]:
    def construct_transport(
        bridge: xbdm_bridge.XBDMBridge,
        remote: socket.socket,
        remote_addr: Tuple[str, int],
    ) -> Optional[ip_transport.IPTransport]:

        ret = GDBTransport(bridge, f"GDB@{remote_addr}")
        ret.set_connection(remote, remote_addr)
        return ret

    return construct_transport
