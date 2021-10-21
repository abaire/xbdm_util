#!/usr/bin/env python3
"""Command line interface for XBDM."""

import argparse
import logging
import sys
from typing import Tuple

from xbdm import connection_manager
from util import shell

XBDM_PORT = 731
logger = logging.getLogger(__name__)


def main(args):
    log_level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(
        level=log_level, format="%(levelname)-8s [%(filename)s:%(lineno)d] %(message)s"
    )

    logger.debug("Startup")

    manager = connection_manager.ConnectionManager()

    xbox_ip, xbox_port = args.xbox
    manager.start_bridge(args.discovery_listen_ip, "XBOX", (xbox_ip, xbox_port))
    bridge = manager.get_bridge((xbox_ip, xbox_port))

    ret = 0
    if not (bridge.can_process_xbdm_commands or bridge.connect_xbdm()):
        print("Failed to communicate with XBOX")
        manager.shutdown()
        return 1

    try:
        command = args.command.lower()
        if command == "shell":
            shell.Shell(bridge).run()
        else:
            command_args = args.command_args
            ret = shell.execute_command(command, command_args, bridge)
        bridge.await_empty_queue()
    except ConnectionResetError:
        print("Connection closed by XBOX")
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
        choices=sorted(shell.DISPATCH_TABLE.keys()),
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
