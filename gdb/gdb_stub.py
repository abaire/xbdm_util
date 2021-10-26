"""Provides a GDB<->XBDM bridge.

See https://sourceware.org/gdb/onlinedocs/gdb/Remote-Protocol.html
See https://www.embecosm.com/appnotes/ean4/embecosm-howto-rsp-server-ean4-issue-2.html
"""

from __future__ import annotations

import binascii
import collections
import errno
import logging
import socket
from typing import Any
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
import util
from xbdm import debugger
from xbdm import xbdm_bridge

logger = logging.getLogger(__name__)

logging.Logger.gdb = util.register_colorized_logging_level(
    "GDB", util.ANSI_BLUE + util.ANSI_BRIGHT_WHITE_BACKGROUND + util.ANSI_BOLD
)
logging.Logger.gdb_send = util.register_colorized_logging_level(
    "<< GDB",
    util.ANSI_BLUE
    + util.ANSI_BRIGHT_WHITE_BACKGROUND
    + util.ANSI_UNDERLINE
    + util.ANSI_BOLD,
)
logging.Logger.gdb_debug = util.register_colorized_super_verbose_logging_level(
    "GDBDBG", util.ANSI_BLUE + util.ANSI_WHITE_BACKGROUND
)


class GDBTransport(ip_transport.IPTransport):
    """GDB Remote Serial Protocol translation of XDBM functions."""

    STATE_INIT = 0
    STATE_CONNECTED = 1

    # Indicates that a request should apply to all threads.
    TID_ALL_THREADS = -1
    # Indicates that a request should apply to any arbitrary thread.
    TID_ANY_THREAD = 0

    ERR_RETRIEVAL_FAILED = 0xD0

    # Breakpoint types
    BP_SOFTWARE = 0
    BP_HARDWARE = 1
    BP_WRITE = 2
    BP_READ = 3
    BP_ACCESS = 4

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
        self._state = self.STATE_INIT
        self._bridge: xbdm_bridge.XBDMBridge = bridge
        self._debugger: Optional[debugger.Debugger] = None
        self._send_queue = collections.deque()

        # Maps a command type to the thread id that should be used when interpreting that command.
        self._command_thread_id_context: Dict[str, int] = {}

        self.features: Dict[str, Any] = {"QStartNoAckMode": False}
        self._dispatch_table: Mapping[
            str, Callable[[GDBPacket], None]
        ] = self._build_dispatch_table(self)

        self._thread_info_buffer: List[int] = []

    def _reset_features(self):
        self.features = {"QStartNoAckMode": False}

    def start(self) -> bool:
        connected = self._bridge.connect_xbdm()
        if not connected:
            logger.error("Failed to connect to XBDM")
            return False

        self._debugger = debugger.Debugger(self._bridge)
        self._debugger.attach()
        self._debugger.halt()

        thread = self._debugger.active_thread
        if thread:
            self._send_thread_stop_packet(thread)
        return True

    def close(self):
        if self._debugger:
            self._debugger.shutdown()
            self._debugger = None

        super().close()
        self._state = self.STATE_INIT

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
        logger.gdb_send(f"Sending GDB packet: {data.decode('utf-8')}")
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

            logger.gdb(f"Processed packet {pkt}")
            # logger.gdb(
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
        command_id = pkt.get_leading_string(2)
        if command_id is not None:
            handler = self._dispatch_table.get(command_id)
            if handler:
                handler(pkt)
                return

        command_id = pkt.get_leading_string(1)
        if command_id is not None:
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
            "z": target._handle_remove_breakpoint_type,
            "Z": target._handle_insert_breakpoint_type,
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
        logger.gdb(f"Ignoring deprecated command: {pkt.data}")
        self.send_packet(GDBPacket())

    def _handle_detach(self, pkt: GDBPacket):
        logger.error(f"Unsupported packet {pkt.data}")
        self.send_packet(GDBPacket())

    def _handle_file_io(self, pkt: GDBPacket):
        logger.error(f"Unsupported packet {pkt.data}")
        self.send_packet(GDBPacket())

    def _handle_read_general_registers(self, pkt: GDBPacket):
        thread_id = self._get_thread_context_for_command("g")
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
                str_value = fmt % socket.htonl(value)

            # logger.gdb(f"{register}: {str_value}")
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
        self._send_ok()

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
        addr, length = pkt.data[1:].split(",")
        addr = int(addr, 16)
        length = int(length, 16)
        mem: Optional[bytes] = self._debugger.get_memory(addr, length)
        if mem:
            self.send_packet(GDBPacket(mem.hex()))
        else:
            self._send_error(errno.EACCES)

    def _handle_write_memory(self, pkt: GDBPacket):
        place, data = pkt.data[1:].split(":")
        addr, length = place.split(",")
        addr = int(addr, 16)
        length = int(length, 16)

        if not length:
            self._send_ok()
            return

        data = binascii.unhexlify(data)
        if length != len(data):
            self._send_error(errno.EBADMSG)
            return
        self._set_memory(addr, data)

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
        if pkt.data == "vCont?":
            self._handle_vcont_query()
            return

        if pkt.data.startswith("vCont;"):
            self._handle_vcont(pkt.data[6:])
            return

        # Suppress error for vMustReplyEmpty, which intentionally follows the same
        # handling as any other unsupported v packet.
        if pkt.data != "vMustReplyEmpty":
            logger.error(f"Unsupported v packet {pkt.data}")
        self._send_empty()

    def _handle_write_memory_binary(self, pkt: GDBPacket):
        place, data = pkt.binary_data[1:].split(b":")

        place = place.decode("utf-8")
        addr, length = place.split(",")
        addr = int(addr, 16)
        length = int(length, 16)

        if not length:
            self._send_ok()
            return

        if length != len(data):
            self._send_error(errno.EBADMSG)
            return
        self._set_memory(addr, data)

    def _set_memory(self, addr: int, data: bytes):
        result = self._debugger.set_memory(addr, data)
        if not result:
            self._send_error(errno.EPIPE)
            return
        self._send_ok()

    @staticmethod
    def _extract_breakpoint_command_params(
        pkt: GDBPacket,
    ) -> Tuple[int, int, int, Optional[List]]:
        elements = pkt.data[1:].split(";")

        type, addr, kind = elements[0].split(",")
        type = int(type)
        addr = int(addr, 16)
        kind = int(kind, 16)

        args = None
        if len(elements) > 1:
            args = elements[1:]

        return type, addr, kind, args

    def _handle_insert_breakpoint_type(self, pkt: GDBPacket):
        type, addr, kind, args = self._extract_breakpoint_command_params(pkt)

        if type == self.BP_SOFTWARE:
            self._handle_insert_software_breakpoint(addr, kind, args)
            return

        if type == self.BP_HARDWARE:
            self._send_empty()
            return

        if type == self.BP_WRITE:
            self._handle_insert_write_breakpoint(addr, kind)
            return

        if type == self.BP_READ:
            self._handle_insert_read_breakpoint(addr, kind)
            return

        if type == self.BP_ACCESS:
            self._handle_insert_access_breakpoint(addr, kind)
            return

        logger.error(f"Unsupported packet {pkt.data}")
        self._send_empty()

    def _handle_insert_software_breakpoint(self, addr, kind, args):
        if kind != 1 or args:
            logger.warning(
                f"Partially supported insert swbreak at 0x%X k: {kind} arg: {args}"
                % addr
            )
        if self._debugger.add_breakpoint_at_address(addr):
            self._send_ok()
            return
        self._send_error(errno.EBADE)

    def _handle_insert_write_breakpoint(self, addr, length):
        if not self._debugger.add_write_watchpoint(addr, length):
            self._send_error(errno.EBADMSG)
        else:
            self._send_ok()

    def _handle_insert_read_breakpoint(self, addr, length):
        if not self._debugger.add_read_watchpoint(addr, length):
            self._send_error(errno.EBADMSG)
        else:
            self._send_ok()

    def _handle_insert_access_breakpoint(self, addr, length):
        if not self._debugger.add_read_watchpoint(addr, length):
            self._send_error(errno.EBADMSG)
            return

        if not self._debugger.add_write_watchpoint(addr, length):
            self._send_error(errno.EBADMSG)
            if not self._debugger.remove_read_watchpoint(addr, length):
                logger.warning(
                    "Failure to add write watchpoint left hanging read watchpoint at 0x%X %d"
                    % (addr, length)
                )
        else:
            self._send_ok()

    def _handle_remove_breakpoint_type(self, pkt: GDBPacket):
        type, addr, kind, _args = self._extract_breakpoint_command_params(pkt)

        if type == self.BP_SOFTWARE:
            self._handle_remove_software_breakpoint(addr, kind)
            return

        if type == self.BP_HARDWARE:
            self._send_empty()
            return

        if type == self.BP_WRITE:
            self._handle_remove_write_breakpoint(addr, kind)
            return

        if type == self.BP_READ:
            self._handle_remove_read_breakpoint(addr, kind)
            return

        if type == self.BP_ACCESS:
            self._handle_remove_access_breakpoint(addr, kind)
            return

        logger.error(f"Unsupported packet {pkt.data}")
        self.send_packet(GDBPacket())

    def _handle_remove_software_breakpoint(self, addr: int, kind: int):
        if kind != 1:
            logger.warning(f"Remove swbreak at 0x%X with kind {kind}" % addr)
        self._debugger.remove_breakpoint_at_address(addr)
        self._send_ok()

    def _handle_remove_write_breakpoint(self, addr, length):
        if not self._debugger.remove_write_watchpoint(addr, length):
            self._send_error(errno.EBADMSG)
        else:
            self._send_ok()

    def _handle_remove_read_breakpoint(self, addr, length):
        if not self._debugger.remove_read_watchpoint(addr, length):
            self._send_error(errno.EBADMSG)
        else:
            self._send_ok()

    def _handle_remove_access_breakpoint(self, addr, length):
        ret = self._debugger.remove_read_watchpoint(addr, length)
        ret = self._debugger.remove_write_watchpoint(addr, length) and ret

        if not ret:
            self._send_error(errno.EBADMSG)
        else:
            self._send_ok()

    def _handle_query_attached(self, _pkt: GDBPacket):
        # If attached to an existing process:
        self.send_packet(GDBPacket("1"))
        # elif started new process
        # self.send_packet(GDBPacket("0"))

    def _handle_query_supported(self, pkt: GDBPacket):
        if self._state != self.STATE_INIT:
            logger.warning("Ignoring assumed qSupported retransmission")
            return

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
                response.append("hwbreak-")
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
                response.append("vContSupported+")
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

        self._state = self.STATE_CONNECTED
        self.send_packet(pkt)

    def _handle_thread_info_start(self):
        self._thread_info_buffer = [thr.thread_id for thr in self._debugger.threads]

        # Move the preferred thread to the front of the list.
        first_id = self._debugger.any_thread_id
        self._thread_info_buffer.remove(first_id)
        self._thread_info_buffer.insert(0, first_id)

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

        logger.gdb(f"Read requested from {target_file} {start} - {end}")
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

    def _handle_vcont_query(self):
        # Support
        #  c - continue
        #  C - continue with signal
        #  s - step
        #  S - step with signal
        self.send_packet(GDBPacket("vcont;c;C;s;S"))

    def _handle_vcont(self, args: str):
        if args == "c":
            logger.warning("TODO: Check that continue_all actually works.")
            self._debugger.continue_all()
            self._send_ok()
        logger.error("TODO: IMPLEMENT _handle_vcont")
        self._send_error(1)

    def _send_empty(self):
        self.send_packet(GDBPacket())

    def _send_ok(self):
        self.send_packet(GDBPacket("OK"))

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
        self._send_ok()

    def _get_thread_context_for_command(self, cmd):
        thread_id = self._command_thread_id_context.get(cmd, None)
        if thread_id is None:
            logger.warning(
                f"Received '{cmd}' command but no thread set! Treating as ANY."
            )
            thread_id = self.TID_ANY_THREAD
        return thread_id


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
