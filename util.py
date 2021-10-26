#!/usr/bin/env python3
"""Command line interface for XBDM."""

import argparse
import logging
import sys
from typing import List
from typing import Tuple

from gdb import gdb_stub
from util import ansi_formatter
from util import commands
from util import debug_logging
from util import shell
from xbdm import bridge_manager
from xbdm import rdcp_command

XBDM_PORT = 731
logger = logging.getLogger(__name__)

_REMOTE_BUILDERS = {
    "gdb": gdb_stub._handle_build_command,
}


def _run_bridge(
    args: List[str],
    manager: bridge_manager.BridgeManager,
    local_ip: str,
    xbox_ip: str,
    xbox_port: int,
) -> int:
    if not args:
        print(f"Usage: bridge [{' | '.join(sorted(_REMOTE_BUILDERS.keys()))}]")
        return 1

    builder_type = args[0].lower()
    builder = _REMOTE_BUILDERS.get(builder_type)
    if not builder:
        print(f"Usage: bridge [{' | '.join(sorted(_REMOTE_BUILDERS.keys()))}]")
        return 1

    builder = builder(args[1:])
    if not builder:
        return 1

    port_index = args.index("port") if "port" in args else -1
    if port_index >= 0:
        local_port = int(args[port_index + 1], 0)
    else:
        local_port = 0

    manager.start_bridge((local_ip, local_port), "XBOX", (xbox_ip, xbox_port), builder)
    bridge = manager.get_bridge((xbox_ip, xbox_port))
    print(f"Connecting to XBDM at {xbox_ip}@{xbox_port}")
    print(f"Listening for {builder_type} connections at {bridge.remote_listen_addr}")

    bridge.connect_xbdm()
    print("Enter 'quit' or 'exit' to shut down.")
    for line in sys.stdin:
        line = line.strip()
        if line.startswith("quit") or line.startswith("exit"):
            print("Exiting gracefully...")
            bridge.send_command(rdcp_command.Bye())
            bridge.await_empty_queue()
            return 0
        print("Enter 'quit' or 'exit' to shut down.")

    return 0


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

    manager = bridge_manager.BridgeManager()
    xbox_ip, xbox_port = args.xbox
    ret = 0

    try:
        command = args.command.lower()
        if command == "bridge":
            ret = _run_bridge(
                args.command_args, manager, args.listen_ip, xbox_ip, xbox_port
            )
        else:
            manager.start_bridge(None, "XBOX", (xbox_ip, xbox_port))
            bridge = manager.get_bridge((xbox_ip, xbox_port))
            assert bridge

            if not (bridge.can_process_xbdm_commands or bridge.connect_xbdm()):
                print("Failed to communicate with XBOX")
                manager.shutdown()
                return 1

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

    known_commands = ["shell", "bridge"]
    known_commands.extend(commands.DISPATCH_TABLE.keys())
    parser.add_argument(
        "command",
        choices=sorted(known_commands),
        help="The command to invoke.",
    )

    parser.add_argument("command_args", nargs="*", help="Parameters for the command.")

    parser.add_argument(
        "-lip",
        "--listen_ip",
        metavar="ip_address",
        default="",
        help="IP address to listen on for bridge connections.",
    )

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
