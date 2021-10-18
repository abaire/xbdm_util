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

        self._panel = wx.Panel(self)
        self._box = wx.BoxSizer(wx.VERTICAL)
        self._panel.SetSizer(self._box)

        self._bridge = xbox_bridge

        if not self._bridge.can_process_xbdm_commands:
            self._wait_text = wx.StaticText(
                self._panel, label=f"Connecting to {xbox_bridge.xbox_info}"
            )
            self._box.Add(self._wait_text, 1, wx.ALL, border=20)
            self._bridge.connect_xbdm_async(self._on_connected)
            return

        self._wait_text = None
        self._on_connected(True)

    def _on_connected(self, success: bool):
        if not success:
            self._wait_text.SetLabel(f"Failed to connect to {self._bridge.xbox_info}")
            return

        self._box.Detach(self._wait_text)
        self._wait_text.Destroy()
        self._wait_text = None

        self._input = wx.ComboBox(
            self._panel, choices=sorted(list(rdcp_command.RDCPCommand.COMMANDS))
        )
        self._go = wx.Button(self._panel, label="Send")
        self._go.Bind(wx.EVT_BUTTON, self._on_send)

        self._box.Add(self._input, 0, wx.ALIGN_CENTER)
        self._box.Add(self._go, 0, wx.BOTTOM | wx.ALIGN_CENTER)

        self._box.Layout()

    def _on_send(self, evt):
        index = self._input.GetSelection()
        if index < 0:
            return

        command = sorted(list(rdcp_command.RDCPCommand.COMMANDS))[index]

        cmd = rdcp_command.RDCPCommand(
            command, response_handler=self._on_command_response
        )
        self._bridge.send_rdcp_command(cmd)

    def _on_command_response(self, response: rdcp_response.RDCPResponse):
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
