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

from gdbxbdmbridge import bridge
from gdbxbdmbridge import discoverer

# xemu NAT can't bind to protected ports.
XBDM_PORT_NAT = 1731
XBDM_PORT = 731


class BridgeManager:
    def __init__(self):
        self._bridges = set()

    def start_bridge(self, listen_ip, xbox_name, xbox_addr):
        self._bridges.add(bridge.GDBXBDMBridge(listen_ip, xbox_name, xbox_addr))

    def shutdown(self):
        print("Shutting down bridges.")
        for bridge in self._bridges:
            bridge.shutdown()
        print("Bridges shut down.")


def main(args):
    print("Startup")

    bridge_manager = BridgeManager()

    def add_bridge(name: str, addr: (str, int)) -> None:
        bridge_manager.start_bridge(args.discovery_listen_ip, name, addr)

    discover = discoverer.XBOXDiscoverer(
        add_bridge, args.discovery_listen_ip, args.discovery_listen_port
    )

    if args.xbox:
        for entry in args.xbox:
            (name, ip, port) = entry[0]
            discover.register(name, (ip, port))

    try:
        discover.start()
        while True:
            time.sleep(1000)
    except KeyboardInterrupt:
        discover.shutdown()
        bridge_manager.shutdown()
        return 0

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

    parser.add_argument(
        "-dip",
        "--discovery_listen_ip",
        nargs=1,
        default="",
        help="IP address to listen on for XBOX devkits.",
    )

    parser.add_argument(
        "-dp",
        "--discovery_listen_port",
        nargs=1,
        type=int,
        default=discoverer.XBOXDiscoverer.XBDM_PORT,
        help="Port to listen on for XBOX devkits.",
    )

    args = parser.parse_args()

    sys.exit(main(args))
