#!/usr/bin/env python3
"""See https://xboxdevwiki.net/Xbox_Debug_Monitor and https://sourceware.org/gdb/onlinedocs/gdb/Remote-Protocol.html"""

import argparse
import logging
import sys
import time
from typing import Tuple

from gdbxbdmbridge import bridge_manager
from gdbxbdmbridge import rdcp_command
from gdbxbdmbridge.bridge import GDBXBDMBridge


XBDM_PORT = 731
logger = logging.getLogger(__name__)


def PrintMemoryWalk(response: rdcp_command.WalkMem.Response):
    response.regions.sort(key=lambda x: x["base_address"])
    for region in response.regions:
        print(
            "Base address: 0x%08X  size: %8d  protection: 0x%X"
            % (region["base_address"], region["size"], region["protection_flags"])
        )


def execute_command(args, bridge: GDBXBDMBridge) -> int:

    cmd = rdcp_command.WalkMem(handler=PrintMemoryWalk)
    bridge.send_rdcp_command(cmd)

    # cmd = rdcp_command.Reboot(rdcp_command.Reboot.FLAG_WARM)
    cmd = rdcp_command.Reboot(rdcp_command.Reboot.FLAG_WAIT)
    bridge.send_rdcp_command(cmd)

    bridge.await_empty_queue()
    return 0


def main(args):
    log_level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(
        level=log_level, format="%(levelname)-8s [%(filename)s:%(lineno)d] %(message)s"
    )

    logger.debug("Startup")

    manager = bridge_manager.BridgeManager()

    xbox_name, xbox_ip, xbox_port = args.xbox
    manager.start_bridge(args.discovery_listen_ip, xbox_name, (xbox_ip, xbox_port))
    bridge = manager.get_bridge((xbox_ip, xbox_port))

    ret = 0
    if bridge.can_process_xbdm_commands or bridge.connect_xbdm():
        ret = execute_command(args, bridge)

    manager.shutdown()
    return ret


def xbox_addr(value) -> (str, Tuple[str, int]):
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
        "xbox",
        metavar="xbox_addr",
        type=xbox_addr,
        help="The xbox to interact with. Format: <name:ip>[:port].",
    )

    parser.add_argument(
        "command",
        choices=["walk_memory"],
        help="The command to invoke.",
    )

    parser.add_argument(
        "-dip",
        "--discovery_listen_ip",
        metavar="ip_address",
        default="",
        help="IP address to listen on for XBOX devkits.",
    )

    parser.add_argument(
        "-v",
        "--verbose",
        help="Enables verbose logging information.",
        action="store_true",
    )

    args = parser.parse_args()

    sys.exit(main(args))
