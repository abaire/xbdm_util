#!/usr/bin/env python3
"""Command line interface for XBDM."""

import argparse
import logging
import sys
from typing import Tuple

from gdbxbdmbridge import bridge_manager
from gdbxbdmbridge import rdcp_command
from gdbxbdmbridge.bridge import GDBXBDMBridge

XBDM_PORT = 731
logger = logging.getLogger(__name__)


def _walk_memory(_args) -> rdcp_command.RDCPCommand:
    def _PrintMemoryWalk(response: rdcp_command.WalkMem.Response):
        response.regions.sort(key=lambda x: x["base_address"])
        for region in response.regions:
            print(
                "Base address: 0x%08X  size: %8d  protection: 0x%X"
                % (
                    region["base_address"],
                    region["size"],
                    region["protection_flags"],
                )
            )

    return rdcp_command.WalkMem(handler=_PrintMemoryWalk)


def _reboot(args: [str]) -> rdcp_command.RDCPCommand:
    modes = {
        "wait": rdcp_command.Reboot.FLAG_WAIT,
        "warm": rdcp_command.Reboot.FLAG_WARM,
        "nodebug": rdcp_command.Reboot.FLAG_NO_DEBUG,
        "stop": rdcp_command.Reboot.FLAG_STOP,
    }

    mode = modes.get(args[0].lower() if args else None)
    if not mode:
        return rdcp_command.Reboot(handler=print)

    return rdcp_command.Reboot(mode, handler=print)


_DISPATCH_TABLE = {
    "reboot": _reboot,
    "walk_mem": _walk_memory,
}


def execute_command(args, bridge: GDBXBDMBridge) -> int:
    command = args.command
    print(command)

    processor = _DISPATCH_TABLE.get(command)
    if not processor:
        print("Invalid command")
        return 1

    cmd = processor(args.command_args)
    if cmd:
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

    xbox_ip, xbox_port = args.xbox
    manager.start_bridge(args.discovery_listen_ip, "XBOX", (xbox_ip, xbox_port))
    bridge = manager.get_bridge((xbox_ip, xbox_port))

    ret = 0
    if bridge.can_process_xbdm_commands or bridge.connect_xbdm():
        try:
            ret = execute_command(args, bridge)
        except:
            manager.shutdown()
            raise

    manager.shutdown()
    return ret


def xbox_addr(value) -> (str, Tuple[str, int]):
    components = value.split(":")
    if len(components) > 2:
        raise argparse.ArgumentTypeError(
            f"XBOX address must be of the form ip[:port={XBDM_PORT}]"
        )
    components = list(components)
    if len(components) == 1:
        components.append(XBDM_PORT)
    else:
        components[1] = int(components[1])
    return tuple(components)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "xbox",
        metavar="xbox_addr",
        type=xbox_addr,
        help="The xbox to interact with. Format: ip[:port].",
    )

    parser.add_argument(
        "command",
        choices=sorted(_DISPATCH_TABLE.keys()),
        help="The command to invoke.",
    )

    parser.add_argument("command_args", nargs="*", help="Parameters for the command.")

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
