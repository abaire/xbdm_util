#!/usr/bin/env python3
"""See https://xboxdevwiki.net/Xbox_Debug_Monitor"""

import collections
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

    def __init__(self, listen_ip="", listen_port=XBDM_PORT):
        self.listen_ip = listen_ip
        self.listen_port = listen_port
        self._xbox_registry_lock = threading.RLock()
        self._xbox_name_registry = collections.defaultdict(set)
        self._xbox_ip_registry = {}

        self._discovery_thread = threading.Thread(
            target=XBOXDiscoverer.discovery_broadcast_thread,
            name="DiscoveryBroadcast",
            args=(self,),
        )
        self._recv_thread = threading.Thread(
            target=XBOXDiscoverer.discovery_recv_thread,
            name="DiscoveryRecv",
            args=(self,),
        )

    def start(self):
        self._discovery_thread.start()
        self._recv_thread.start()

    @staticmethod
    def discovery_broadcast_thread(discoverer):
        print("Broadcast thread started")
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

        discovery_packet = NAPPacket.build_discovery_packet()

        while True:
            time.sleep(DISCOVERY_BROADCAST_INTERVAL_SECONDS)
            bytes_sent = sock.sendto(
                discovery_packet.serialize(), ("<broadcast>", discoverer.listen_port)
            )
            if bytes_sent != 2:
                print("ERROR: Failed to send discovery packet.")

    @staticmethod
    def discovery_recv_thread(discoverer):
        print("Recv thread started")
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind((discoverer.listen_ip, discoverer.listen_port))

        reply_packet = NAPPacket()

        while True:
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
            with discoverer._xbox_registry_lock:
                discoverer._xbox_name_registry[reply_packet.name].add(addr)
                discoverer._xbox_ip_registry[addr] = reply_packet.name


def main():
    print("Startup")
    discoverer = XBOXDiscoverer()
    discoverer.start()

    while True:
        time.sleep(1000)
    # sock = socket.socket(socket.AF_INET, # Internet
    #                      socket.SOCK_DGRAM) # UDP
    # sock.sendto(MESSAGE, (UDP_IP, UDP_PORT))

    # sock = socket.socket(socket.AF_INET, # Internet
    #                      socket.SOCK_DGRAM) # UDP
    # sock.bind((UDP_IP, UDP_PORT))

    # while True:
    #     data, addr = sock.recvfrom(1024) # buffer size is 1024 bytes
    #     print("received message: %s" % data)

    return 0


if __name__ == "__main__":
    sys.exit(main())
