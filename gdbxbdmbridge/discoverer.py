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
        self.type, name_len = struct.unpack("BB", buffer[:2])
        self.name = str(buffer[2 : 2 + name_len])
        return 2 + name_len


class XBOXDiscoverer:
    """Broadcasts and handles responses to NAP discovery packets."""

    XBDM_PORT = 731

    # Interval between NAP discovery packets.
    DISCOVERY_BROADCAST_INTERVAL_SECONDS = 2

    def __init__(
        self,
        listen_ip="",
        xbdm_port=XBDM_PORT,
        on_discover: Callable[[str, (str, int)], None] = None,
    ):
        self.listen_ip = listen_ip
        self.xbdm_port = xbdm_port
        self.broadcast_interval = self.DISCOVERY_BROADCAST_INTERVAL_SECONDS
        self.on_discover = on_discover
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

    def set_on_discover_callback(self, on_discover: Callable[[str, (str, int)], None]):
        self.on_discover = on_discover

    def get_registered_devices(self) -> [str, (str, int)]:
        with self._xbox_registry_lock:
            return list(self._xbox_ip_registry.items())

    def register(self, name, addr):
        with self._xbox_registry_lock:
            if addr in self._xbox_ip_registry:
                if name != self._xbox_ip_registry[addr]:
                    print("TODO: Handle XBOX device renaming gracefully")
                return

            self._xbox_name_registry[name].add(addr)
            self._xbox_ip_registry[addr] = name

        if self.on_discover:
            self.on_discover(name, addr)

    def shutdown(self):
        print("Shutting down discovery process.")
        self._running = False
        self._discovery_thread.join()
        print("Exited discovery process.")

    def _thread_main(self):
        broadcast_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        broadcast_sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        broadcast_sock.bind((self.listen_ip, 0))
        discovery_packet = NAPPacket.build_discovery_packet()

        last_broadcast = time.time() - self.broadcast_interval
        while self._running:
            readable = [broadcast_sock]
            exceptional = readable[:]

            elapsed_time = time.time() - last_broadcast
            if elapsed_time >= self.broadcast_interval:
                writable = [broadcast_sock]
                last_broadcast = time.time()
            else:
                writable = []

            readable, writable, exceptional = select.select(
                readable, writable, exceptional, self.broadcast_interval
            )

            if broadcast_sock in readable:
                data, addr = broadcast_sock.recvfrom(277)
                self._parse_response(data, addr)

            if broadcast_sock in writable:
                bytes_sent = broadcast_sock.sendto(
                    discovery_packet.serialize(), ("<broadcast>", self.xbdm_port)
                )
                if bytes_sent != 2:
                    print("ERROR: Failed to send discovery packet.")

        broadcast_sock.close()

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
