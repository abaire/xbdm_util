import logging
import wx

from gdbxbdmbridge import bridge
from gdbxbdmbridge import rdcp_command
from gdbxbdmbridge import rdcp_response

logger = logging.getLogger(__name__)


class XBDMDialog(wx.Dialog):
    """Dialog providing tools for interacting with an XBOX devkit."""

    def __init__(self, parent, xbox_bridge: bridge.GDBXBDMBridge, *args, **kw):
        super().__init__(parent, *args, title=xbox_bridge.xbox_info, **kw)

        self._bridge = xbox_bridge

        if not self._bridge.can_process_xbdm_commands:
            self._wait_text = wx.StaticText(
                self, label=f"Connecting to {xbox_bridge.xbox_info}"
            )
            self._bridge.connect_xbdm_async(lambda success: self._on_connected(success))
            return

        self._wait_text = None
        self._on_connected(True)

    def _on_connected(self, success: bool):
        if not success:
            self._wait_text.SetLabel(f"Failed to connect to {self._bridge.xbox_info}")
            return

        self._wait_text.Destroy()
        self._wait_text = None

        cmd = rdcp_command.DriveList(lambda response: self._on_drive_list(response))
        self._bridge.send_rdcp_command(cmd)

        cmd = rdcp_command.RDCPCommand(
            "systime", response_handler=lambda response: self._on_systime(response)
        )
        self._bridge.send_rdcp_command(cmd)

    def _on_systime(self, response: rdcp_response.RDCPResponse):
        logging.info(response)
        return True

    def _on_drive_list(self, response: rdcp_command.DriveList.Response):
        logging.info(response)

        cmd = rdcp_command.DriveFreeSpace(
            response.drives[0],
            lambda r: self._on_drive_free_space(response.drives[0], r),
        )
        self._bridge.send_rdcp_command(cmd)

        return True

    def _on_drive_free_space(
        self, drive_letter, response: rdcp_command.DriveFreeSpace.Response
    ):
        logging.info(f"Free space on {drive_letter}: {response}")
        return True
