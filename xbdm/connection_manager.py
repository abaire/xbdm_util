import logging
from typing import Optional
from typing import Tuple

from . import xbdm_connection
from . import xbdm_connection_info

logger = logging.getLogger(__name__)


class ConnectionManager:
    """Manages a set of XBDMConnection instances."""

    def __init__(self):
        self._bridges: {Tuple[str, int]: xbdm_connection.XBDMConnection} = {}

    def start_bridge(
        self, listen_ip: str, xbox_name: str, xbox_addr: Tuple[str, int]
    ) -> Tuple[str, int]:
        old_bridge: xbdm_connection.XBDMConnection = self._bridges.get(xbox_addr, None)
        if old_bridge:
            return old_bridge.listen_addr

        logger.info(f"Adding bridge to {xbox_name}@{xbox_addr}")
        new_bridge = xbdm_connection.XBDMConnection(listen_ip, xbox_name, xbox_addr)
        self._bridges[xbox_addr] = new_bridge
        return new_bridge.listen_addr

    def shutdown(self):
        logger.info("Shutting down bridges.")
        for bridge in self._bridges.values():
            bridge.shutdown()
        self._bridges.clear()
        logger.info("Bridges shut down.")

    def get_bridge_infos(self) -> [xbdm_connection_info.ConnectionInfo]:
        ret = []
        for bridge in self._bridges.values():
            ret.append(
                xbdm_connection_info.ConnectionInfo(
                    bridge.listen_addr, bridge.xbox_name, bridge.xbox_addr
                )
            )
        return ret

    def get_bridge(
        self, xbox_addr: Tuple[str, int]
    ) -> Optional[xbdm_connection.XBDMConnection]:
        return self._bridges.get(xbox_addr)
