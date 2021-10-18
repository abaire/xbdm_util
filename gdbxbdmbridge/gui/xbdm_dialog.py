import wx

from gdbxbdmbridge import bridge
from gdbxbdmbridge import rdcp_command
from gdbxbdmbridge import rdcp_response


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

        cmd = rdcp_command.RDCPCommand(
            "threads", response_handler=lambda response: self._on_systime(response)
        )
        self._bridge.send_rdcp_command(cmd)

    def _on_systime(self, response: rdcp_response.RDCPResponse):
        print(response)
        return True
