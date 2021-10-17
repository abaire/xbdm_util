#!/usr/bin/env python3
"""See https://xboxdevwiki.net/Xbox_Debug_Monitor"""

import argparse
import collections
import select
import socket
import struct
import sys
import threading
import time

# xemu NAT can't bind to protected ports.
XBDM_PORT_NAT = 1731
XBDM_PORT = 731

# Interval between NAP discovery packets.
DISCOVERY_BROADCAST_INTERVAL_SECONDS = 0.75


class RDCPCommand:
    STATUS_CODES = {
        0: "INVALID",
        200: "OK",
        201: "connected",
        202: "multiline response follows",
        203: "binary response follows",
        204: "send binary data",
        205: "connection dedicated",
        400: "unexpected error",
        401: "max number of connections exceeded",
        402: "file not found",
        403: "no such module",
        404: "memory not mapped",
        405: "no such thread",
        406: "failed to set system time",
        407: "unknown command",
        408: "not stopped",
        409: "file must be copied",
        410: "file already exists",
        411: "directory not empty",
        412: "filename is invalid",
        413: "file cannot be created",
        414: "access denied",
        415: "no room on device",
        416: "not debuggable",
        417: "type invalid",
        418: "data not available",
        420: "box not locked",
        421: "key exchange required",
        422: "dedicated connection required",
    }

    COMMANDS = {
        "adminpw",
        "altaddr",
        "authuser",
        "boxid",
        "break",
        "bye",
        "capcontrol",
        "continue",
        "crashdump",
        "d3dopcode",
        "dbgname",
        "dbgoptions",
        "debugger",
        "debugmode",
        "dedicate",
        "deftitle",
        "delete",
        "dirlist",
        "dmversion",
        "drivefreespace",
        "drivelist",
        "dvdblk",
        "dvdperf",
        "fileeof",
        "flash",
        "fmtfat",
        "funccall",
        "getcontext",
        "getd3dstate",
        "getextcontext",
        "getfile",
        "getfileattributes",
        "getgamma",
        "getmem",
        "getmem2",
        "getpalette",
        "getpid",
        "getsum",
        "getsurf",
        "getuserpriv",
        "getutildrvinfo",
        "go",
        "gpucount",
        "halt",
        "irtsweep",
        "isbreak",
        "isdebugger",
        "isstopped",
        "kd",
        "keyxchg",
        "lockmode",
        "lop",
        "magicboot",
        "memtrack",
        "mkdir",
        "mmglobal",
        "modlong",
        "modsections",
        "modules",
        "nostopon",
        "notify",
        "notifyat",
        "pbsnap",
        "pclist",
        "pdbinfo",
        "pssnap",
        "querypc",
        "reboot",
        "rename",
        "resume",
        "screenshot",
        "sendfile",
        "servname",
        "setconfig",
        "setcontext",
        "setfileattributes",
        "setsystime",
        "setuserpriv",
        "signcontent",
        "stop",
        "stopon",
        "suspend",
        "sysfileupd",
        "systime",
        "threadinfo",
        "threads",
        "title",
        "user",
        "userlist",
        "vssnap",
        "walkmem",
        "writefile",
        "xbeinfo",
        "xtlinfo",
    }

    TERMINATOR = b"\r\n"

    def __init__(self):
        self.status = 0
        self.data = []

    def __str__(self):
        size = len(self.data)
        return (
            f"{self.status}:{self.STATUS_CODES.get(self.status, '??INVALID??')}[{size}]"
        )

    def parse(self, buffer: bytes):
        terminator = buffer.find(self.TERMINATOR)
        if terminator < 0:
            return 0

        if buffer[3] != ord("-"):
            print(f"Received non RDCP packet {buffer}: {buffer[3]} != '-'")
            return -1

        status = buffer[:3]
        self.status = int(status)
        self.data = buffer[4:terminator]

        print(self)
        return terminator + len(self.TERMINATOR)


class NAPPacket:
    """Models an NAP discovery packet."""

    TYPE_INVALID = 0
    TYPE_LOOKUP = 1
    TYPE_REPLY = 2
    TYPE_WILDCARD = 3

    @classmethod
    def build_discovery_packet(cls):
        return cls(cls.TYPE_WILDCARD)

    def __init__(self, typ=TYPE_INVALID, name=""):
        self.type = typ
        self.name = name

    def serialize(self):
        ret = struct.pack("Bp", self.type, bytes(self.name, "utf-8"))
        return ret

    def deserialize(self, buffer):
        self.type, self.name = struct.unpack("Bp", buffer)
        return 2 + len(self.name)


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
        self._xbdm_sock.connect(self.xbox_addr)
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
        cmd = RDCPCommand()

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


class XBOXDiscoverer:
    """Broadcasts and handles responses to NAP discovery packets."""

    def __init__(self, listen_ip="", listen_port=XBDM_PORT):
        self.listen_ip = listen_ip
        self.listen_port = listen_port
        self._xbox_registry_lock = threading.RLock()
        self._xbox_name_registry = collections.defaultdict(set)
        self._xbox_ip_registry = {}

        self._bridges = set()
        self._running = False

        self._discovery_thread = threading.Thread(
            target=XBOXDiscoverer._discovery_broadcast_thread_main,
            name="DiscoveryBroadcast",
            args=(self,),
        )
        self._recv_thread = threading.Thread(
            target=XBOXDiscoverer._discovery_recv_thread_main,
            name="DiscoveryRecv",
            args=(self,),
        )

    def start(self):
        self._running = True
        self._discovery_thread.start()
        self._recv_thread.start()

    def register(self, name, addr):
        with self._xbox_registry_lock:
            self._xbox_name_registry[name].add(addr)
            self._xbox_ip_registry[addr] = name

        self._start_bridge(name, addr)

    def shutdown(self):
        self._running = False
        for bridge in self._bridges:
            bridge.shutdown()
        self._discovery_thread.join()
        self._recv_thread.join()

    def _start_bridge(self, name, addr):
        self._bridges.add(GDBXBDMBridge(self.listen_ip, name, addr))

    @staticmethod
    def _discovery_broadcast_thread_main(discoverer):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

        discovery_packet = NAPPacket.build_discovery_packet()

        while discoverer._running:
            time.sleep(DISCOVERY_BROADCAST_INTERVAL_SECONDS)
            bytes_sent = sock.sendto(
                discovery_packet.serialize(), ("<broadcast>", discoverer.listen_port)
            )
            if bytes_sent != 2:
                print("ERROR: Failed to send discovery packet.")

    @staticmethod
    def _discovery_recv_thread_main(discoverer):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind((discoverer.listen_ip, discoverer.listen_port))

        reply_packet = NAPPacket()

        while discoverer._running:
            # TODO: Make non-blocking so _running can be checked.
            data, addr = sock.recvfrom(277)

            if len(data) < 2:
                print("Ignoring unexpected data")
                continue

            bytes_consumed = reply_packet.deserialize(data)
            if len(data) != bytes_consumed:
                print(
                    f"Received unexpected non-NAP packet with type: {reply_packet.TYPE_REPLY} from {addr}"
                )
                continue

            if reply_packet.type != reply_packet.TYPE_REPLY:
                # Ignore any lookups or wildcard requests.
                continue

            print("XBOX discovered at {addr}")
            discoverer.register(reply_packet.name, addr)


def main(args):
    print("Startup")
    discoverer = XBOXDiscoverer()

    for entry in args.xbox:
        (name, ip, port) = entry[0]
        discoverer.register(name, (ip, port))

    try:
        discoverer.start()
        while True:
            time.sleep(1000)
    except KeyboardInterrupt:
        discoverer.shutdown()
        raise

    return 0


def xbox_addr(value):
    components = value.split(":")
    if len(components) < 2 or len(components) > 3:
        raise argparse.ArgumentTypeError(
            f"XBOX address must be of the form name:ip[:port={XBDM_PORT}]"
        )
    components = list(components)
    if len(components) == 2:
        components.append(XBDM_PORT)
    else:
        components[2] = int(components[2])
    return tuple(components)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-x",
        "--xbox",
        nargs=1,
        metavar="xbox_addr",
        action="append",
        type=xbox_addr,
        help="Forces the presence of an XBOX debug kit. Format: <name:ip>[:port].",
    )

    args = parser.parse_args()

    sys.exit(main(args))
