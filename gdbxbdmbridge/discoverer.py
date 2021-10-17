"""Provides discovery of XBDM-enabled XBOXes."""
import collections
import select
import socket
import struct
import threading
import time
from typing import Callable


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


class XBOXDiscoverer:
    """Broadcasts and handles responses to NAP discovery packets."""

    XBDM_PORT = 731

    # Interval between NAP discovery packets.
    DISCOVERY_BROADCAST_INTERVAL_SECONDS = 0.75

    def __init__(
        self,
        on_registered: Callable[[str, (str, int)], None],
        listen_ip="",
        listen_port=XBDM_PORT,
    ):
        self.listen_ip = listen_ip
        self.listen_port = listen_port
        self.broadcast_interval = self.DISCOVERY_BROADCAST_INTERVAL_SECONDS
        self.on_registered = on_registered
        self._xbox_registry_lock = threading.RLock()
        self._xbox_name_registry = collections.defaultdict(set)
        self._xbox_ip_registry = {}

        self._running = False

        self._discovery_thread = threading.Thread(
            target=lambda x: x._thread_main(),
            name="XBOXDiscoverer",
            args=(self,),
        )

    def start(self):
        self._running = True
        self._discovery_thread.start()

    def register(self, name, addr):
        print("REGISTER")
        with self._xbox_registry_lock:
            self._xbox_name_registry[name].add(addr)
            self._xbox_ip_registry[addr] = name

        if self.on_registered:
            self.on_registered(name, addr)

    def shutdown(self):
        print("Shutting down discovery process.")
        self._running = False
        self._discovery_thread.join()
        print("Exited discovery process.")

    def _thread_main(self):
        broadcast_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        broadcast_sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

        recv_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        recv_sock.bind((self.listen_ip, self.listen_port))

        discovery_packet = NAPPacket.build_discovery_packet()

        last_broadcast = time.time() - self.broadcast_interval
        while self._running:
            readable = [recv_sock]
            exceptional = [recv_sock]

            elapsed_time = time.time() - last_broadcast
            if elapsed_time >= self.broadcast_interval:
                writable = [broadcast_sock]
                last_broadcast = time.time()
            else:
                writable = []

            readable, writable, exceptional = select.select(
                readable, writable, exceptional, self.broadcast_interval
            )

            if recv_sock in readable:
                data, addr = recv_sock.recvfrom(277)
                self._parse_response(data, addr)

            if broadcast_sock in writable:
                bytes_sent = broadcast_sock.sendto(
                    discovery_packet.serialize(), ("<broadcast>", self.listen_port)
                )
                if bytes_sent != 2:
                    print("ERROR: Failed to send discovery packet.")

    def _parse_response(self, data: bytes, addr: (str, int)) -> None:
        reply_packet = NAPPacket()

        if len(data) < 2:
            print("Ignoring unexpected data")
            return

        bytes_consumed = reply_packet.deserialize(data)
        if len(data) != bytes_consumed:
            print(
                f"Received unexpected non-NAP packet with type: {reply_packet.TYPE_REPLY} from {addr}"
            )
            return

        if reply_packet.type != reply_packet.TYPE_REPLY:
            # Ignore any lookups or wildcard requests.
            return

        self.register(reply_packet.name, addr)
