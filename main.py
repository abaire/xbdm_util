#!/usr/bin/env python3
import socket
import struct
import sys
import threading
import time

# xemu NAT can't bind to protected ports.
XBDM_PORT_NAT = 1731
XBDM_PORT = 731

# Interval between NAP discovery packets.
DISCOVERY_BROADCAST_INTERVAL_SECONDS = 0.5


class NAPPacket:
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


def discovery_broadcast_thread():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

    discovery_packet = NAPPacket.build_discovery_packet()

    while True:
        time.sleep(DISCOVERY_BROADCAST_INTERVAL_SECONDS)
        bytes_sent = sock.sendto(discovery_packet.serialize(), ("<broadcast>", XBDM_PORT))
        if (bytes_sent != 2):
            print("ERROR: Failed to send discovery packet.")


def discovery_recv_thread(listen_ip):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((listen_ip, XBDM_PORT))

    reply_packet = NAPPacket()

    while True:
        data, addr = sock.recvfrom(277)

        if (len(data) < 2):
            print("Ignoring unexpected data")
            continue

        bytes_consumed = reply_packet.deserialize(data)
        if (len(data) != bytes_consumed or reply_packet.type != reply_packet.TYPE_REPLY):
            print(f"Received unexpected non-NAP packet with type: {reply_packet.TYPE_REPLY}")
            continue

        print("XBOX discovered at {addr}")


def main():

    threading.Thread(target=discovery_broadcast_thread)
    threading.Thread(target=discovery_recv_thread, args=('',))

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
