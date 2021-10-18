#!/usr/bin/env python3
"""See https://xboxdevwiki.net/Xbox_Debug_Monitor and https://sourceware.org/gdb/onlinedocs/gdb/Remote-Protocol.html"""

import argparse
import sys
import time

from gdbxbdmbridge import bridge_manager
from gdbxbdmbridge import discoverer

XBDM_PORT = 731


def main(args):
    print("Startup")

    manager = bridge_manager.BridgeManager()
    xbox_discoverer = discoverer.XBOXDiscoverer(
        args.discovery_listen_ip, args.discovery_port
    )

    # TODO: Support console-only mode
    from gdbxbdmbridge import gui

    app = gui.Application(xbox_discoverer, manager)

    def add_bridge(name: str, addr: (str, int)) -> None:
        manager.start_bridge(args.discovery_listen_ip, name, addr)
        if app:
            app.refresh_discovered_devices()

    xbox_discoverer.set_on_discover_callback(add_bridge)

    if args.xbox:
        for entry in args.xbox:
            (name, ip, port) = entry[0]
            xbox_discoverer.register(name, (ip, port))

    try:
        xbox_discoverer.start()
        if app:
            app.MainLoop()
        else:
            while True:
                time.sleep(1000)
    except KeyboardInterrupt:
        xbox_discoverer.shutdown()
        manager.shutdown()
        return 0

    xbox_discoverer.shutdown()
    manager.shutdown()
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
        "--discovery_port",
        nargs=1,
        type=int,
        default=discoverer.XBOXDiscoverer.XBDM_PORT,
        help="Port on which XBDM listens for discovery of XBOX devkits.",
    )

    args = parser.parse_args()

    sys.exit(main(args))
