import logging
from typing import Optional
from typing import Tuple

from . import bridge
from . import bridge_info

logger = logging.getLogger(__name__)


class BridgeManager:
    """Manages a set of GDBXBDMBridge instances."""

    def __init__(self):
        self._bridges: {Tuple[str, int]: bridge.GDBXBDMBridge} = {}

    def start_bridge(
        self, listen_ip: str, xbox_name: str, xbox_addr: Tuple[str, int]
    ) -> Tuple[str, int]:
        old_bridge: bridge.GDBXBDMBridge = self._bridges.get(xbox_addr, None)
        if old_bridge:
            return old_bridge.listen_addr

        logger.info(f"Adding bridge to {xbox_name}@{xbox_addr}")
        new_bridge = bridge.GDBXBDMBridge(listen_ip, xbox_name, xbox_addr)
        self._bridges[xbox_addr] = new_bridge
        return new_bridge.listen_addr

    def shutdown(self):
        logger.info("Shutting down bridges.")
        for bridge in self._bridges.values():
            bridge.shutdown()
        self._bridges.clear()
        logger.info("Bridges shut down.")

    def get_bridge_infos(self) -> [bridge_info.BridgeInfo]:
        ret = []
        for bridge in self._bridges.values():
            ret.append(
                bridge_info.BridgeInfo(
                    bridge.listen_addr, bridge.xbox_name, bridge.xbox_addr
                )
            )
        return ret

    def get_bridge(self, xbox_addr: Tuple[str, int]) -> Optional[bridge.GDBXBDMBridge]:
        return self._bridges.get(xbox_addr)
