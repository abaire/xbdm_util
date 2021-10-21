#!/usr/bin/env python3
"""Runs NAP discovery and reports any devices on the network."""

import argparse
import logging
import sys
import time
from typing import Tuple

from xbdm import discoverer

XBDM_PORT = 731
logger = logging.getLogger(__name__)


def main(args):
    log_level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(
        level=log_level, format="%(levelname)-8s [%(filename)s:%(lineno)d] %(message)s"
    )

    logger.debug("Startup")

    xbox_discoverer = discoverer.XBOXDiscoverer(
        args.discovery_listen_ip, args.discovery_port
    )

    def print_info(name: str, addr: Tuple[str, int]) -> None:
        print(f'XBOX "{name}" at {addr[0]}:{addr[1]}')

    xbox_discoverer.set_on_discover_callback(print_info)

    try:
        xbox_discoverer.start()
        time.sleep(args.wait_time)
    except KeyboardInterrupt:
        xbox_discoverer.shutdown()
        return 0

    xbox_discoverer.shutdown()
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
        "-w",
        "--wait_time",
        metavar="seconds",
        type=float,
        default=30,
        help="Number of seconds to wait for responses before exiting.",
    )

    parser.add_argument(
        "-dip",
        "--discovery_listen_ip",
        metavar="ip_address",
        default="",
        type=str,
        help="IP address to listen on for XBOX devkits.",
    )

    parser.add_argument(
        "-dp",
        "--discovery_port",
        metavar="port",
        type=int,
        default=discoverer.XBOXDiscoverer.XBDM_PORT,
        help="Port on which XBDM listens for discovery of XBOX devkits.",
    )

    parser.add_argument(
        "-v",
        "--verbose",
        help="Enables verbose logging information.",
        action="store_true",
    )

    args = parser.parse_args()

    sys.exit(main(args))
