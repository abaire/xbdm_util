import logging
from typing import Optional
from typing import Tuple

from . import xbdm_bridge
from . import xbdm_connection_info

logger = logging.getLogger(__name__)


class BridgeManager:
    """Manages a set of XBDMBridge instances."""

    def __init__(self):
        self._bridges: {Tuple[str, int]: xbdm_bridge.XBDMBridge} = {}

    def start_bridge(
        self, xbox_name: str, xbox_addr: Tuple[str, int]
    ) -> xbdm_bridge.XBDMBridge:
        old_bridge: xbdm_bridge.XBDMBridge = self._bridges.get(xbox_addr, None)
        if old_bridge:
            return old_bridge

        logger.info(f"Adding bridge to {xbox_name}@{xbox_addr}")
        new_bridge = xbdm_bridge.XBDMBridge(xbox_name, xbox_addr)
        self._bridges[xbox_addr] = new_bridge
        return new_bridge

    def shutdown(self):
        logger.info("Shutting down bridges.")
        for bridge in self._bridges.values():
            bridge.shutdown()
        self._bridges.clear()
        logger.info("Bridges shut down.")

    def get_bridge_infos(self) -> [xbdm_connection_info.ConnectionInfo]:
        ret = []
        bridge: xbdm_bridge.XBDMBridge
        for bridge in self._bridges.values():
            ret.append(
                xbdm_connection_info.ConnectionInfo(
                    bridge.remote_listen_addr, bridge.xbox_name, bridge.xbox_addr
                )
            )
        return ret

    def get_bridge(
        self, xbox_addr: Tuple[str, int]
    ) -> Optional[xbdm_bridge.XBDMBridge]:
        return self._bridges.get(xbox_addr)
