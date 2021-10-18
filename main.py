#!/usr/bin/env python3
"""See https://xboxdevwiki.net/Xbox_Debug_Monitor"""

import argparse
import sys

import wx

from gdbxbdmbridge import bridge_manager
from gdbxbdmbridge import discoverer
from gdbxbdmbridge import gui

XBDM_PORT = 731


def main(args):
    print("Startup")

    manager = bridge_manager.BridgeManager()
    xbox_discoverer = discoverer.XBOXDiscoverer(
        args.discovery_listen_ip, args.discovery_port
    )

    app = wx.App()
    frame = gui.MainFrame(title="GDB <-> XBDM Bridge")
    frame.set_discovered_devices(xbox_discoverer.get_registered_devices())
    frame.Show()

    frame.Bind(gui.MainFrame.EVT_LAUNCH_XBDM_BROWSER, launch_xbdm_browser)

    def add_bridge(name: str, addr: (str, int)) -> None:
        manager.start_bridge(args.discovery_listen_ip, name, addr)
        frame.set_discovered_devices(manager.get_bridge_infos())

    xbox_discoverer.set_on_discover_callback(add_bridge)

    if args.xbox:
        for entry in args.xbox:
            (name, ip, port) = entry[0]
            xbox_discoverer.register(name, (ip, port))

    try:
        xbox_discoverer.start()
        app.MainLoop()
        xbox_discoverer.shutdown()
        manager.shutdown()

    except KeyboardInterrupt:
        xbox_discoverer.shutdown()
        manager.shutdown()
        return 0

    return 0


def launch_xbdm_browser(evt: gui.MainFrame.LaunchXBDMBrowserEvent):
    xbox_addr = evt.addr
    print(xbox_addr)


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
