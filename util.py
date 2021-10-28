#!/usr/bin/env python3
"""Command line interface for XBDM."""

import argparse
import logging
import sys
from typing import List
from typing import Tuple

from gdb import transport
from util import ansi_formatter
from util import commands
from util import debug_logging
from util import shell
from xbdm import bridge_manager
from xbdm import rdcp_command
from xbdm import xbdm_bridge

XBDM_PORT = 731
logger = logging.getLogger(__name__)


def main(args):
    if args.super_verbose:
        log_level = debug_logging.SUPER_VERBOSE
    elif args.verbose:
        log_level = logging.DEBUG
    else:
        log_level = logging.INFO

    logging.basicConfig(level=log_level)
    if args.color:
        ansi_formatter.colorize_logs()

    logger.debug("Startup")

    xbox_ip, xbox_port = args.xbox
    manager = bridge_manager.BridgeManager()
    bridge: xbdm_bridge.XBDMBridge = manager.start_bridge("XBOX", (xbox_ip, xbox_port))

    try:
        command = args.command.lower()
        if not (
            command == "bridge"
            or bridge.can_process_xbdm_commands
            or bridge.connect_xbdm()
        ):
            print("Failed to communicate with XBOX")
            manager.shutdown()
            return 1

        instance = shell.Shell(bridge)
        if command == "shell":
            instance.run()
        else:
            command_args = args.command_args
            instance.execute_command(command, command_args)

            if command == "bridge":
                instance.run()

        bridge.await_empty_queue()

    except ConnectionResetError:
        print("Connection closed by XBOX")
    except:
        manager.shutdown()
        raise

    manager.shutdown()
    return 0


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

    known_commands = ["shell", "bridge"]
    known_commands.extend(commands.DISPATCH_TABLE.keys())
    parser.add_argument(
        "command",
        choices=sorted(known_commands),
        help="The command to invoke.",
    )

    parser.add_argument("command_args", nargs="*", help="Parameters for the command.")

    parser.add_argument(
        "-c",
        "--color",
        help="Enables colorized logs.",
        action="store_true",
    )

    parser.add_argument(
        "-v",
        "--verbose",
        help="Enables verbose logging information.",
        action="store_true",
    )

    parser.add_argument(
        "-vv",
        "--super_verbose",
        help="Enables all logging information.",
        action="store_true",
    )

    args = parser.parse_args()

    sys.exit(main(args))
