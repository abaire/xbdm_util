import logging
import wx
from wx.lib import newevent

from gdbxbdmbridge import bridge
from gdbxbdmbridge import rdcp_command
from gdbxbdmbridge import rdcp_response

logger = logging.getLogger(__name__)


TEST_COMMANDS = [
    "adminpw",
    # "altaddr",  #  addr=0x0a000210
    "authuser",
    # "boxid",  # Can only be executed if security is enabled.
    "break",
    # "bye",
    "capctrl",
    "continue",
    "crashdump",
    "d3dopcode",
    "dbgname",
    "dbgoptions",
    "debugger",
    "debugmode",
    "dedicate",
    "deftitle",
    "delete",
    "dirlist",
    "dmversion",
    "drivefreespace",
    "drivelist",
    "dvdblk",
    "dvdperf",
    "fileeof",
    "flash",
    "fmtfat",
    "funccall",
    "getcontext",
    "getd3dstate",
    "getextcontext",
    "getfile",
    "getfileattributes",
    "getgamma",
    "getmem",
    "getmem2",
    "getpalette",
    "getpid",
    "getsum",
    "getsurf",
    "getuserpriv",
    "getutildrvinfo",
    "go",
    "gpucount",
    "halt",
    "irtsweep",
    "isbreak",
    "isdebugger",
    "isstopped",
    "kd",
    "keyxchg",
    "lockmode",
    "lop",
    "magicboot",
    "memtrack",
    "mkdir",
    "mmglobal",
    "modlong",
    "modsections",
    "modules",
    "nostopon",
    "notify",
    "notifyat",
    "pbsnap",
    "pclist",
    "pdbinfo",
    "pssnap",
    "querypc",
    "reboot",
    "rename",
    "resume",
    "screenshot",
    "sendfile",
    "servname",
    "setconfig",
    "setcontext",
    "setfileattributes",
    "setsystime",
    "setuserpriv",
    "signcontent",
    "stop",
    "stopon",
    "suspend",
    "sysfileupd",
    "systime",  # high=0x1d7c3df low=0xb7852a80
    "threadinfo",
    "threads",
    "title",
    "user",
    "userlist",
    "vssnap",
    "walkmem",
    "writefile",
    "xbeinfo",
    "xtlinfo",
]


class XBDMDialog(wx.Dialog):
    """Dialog providing tools for interacting with an XBOX devkit."""

    ConnectedEvent, EVT_CONNECTED = newevent.NewEvent()

    def __init__(self, parent, xbox_bridge: bridge.GDBXBDMBridge, *args, **kw):
        super().__init__(parent, *args, title=xbox_bridge.xbox_info, **kw)

        self._panel = wx.Panel(self)
        self._box = wx.BoxSizer(wx.VERTICAL)
        self._panel.SetSizer(self._box)

        self._bridge = xbox_bridge
        self.Bind(self.EVT_CONNECTED, self._on_connected)

        if not self._bridge.can_process_xbdm_commands:
            self._wait_text = wx.StaticText(
                self._panel, label=f"Connecting to {xbox_bridge.xbox_info}"
            )
            self._box.Add(self._wait_text, 1, wx.ALL, border=20)
            self._bridge.connect_xbdm_async(
                lambda success: wx.PostEvent(
                    self, self.ConnectedEvent(id=wx.ID_ANY, success=success)
                )
            )
            return

        self._wait_text = None
        wx.PostEvent(self, self.ConnectedEvent(id=wx.ID_ANY, success=True))

    def _on_connected(self, evt):
        success = evt.success
        if not success:
            self._wait_text.SetLabel(f"Failed to connect to {self._bridge.xbox_info}")
            return

        self._box.Detach(self._wait_text)
        self._wait_text.Destroy()
        self._wait_text = None

        self._input = wx.ComboBox(self._panel, choices=TEST_COMMANDS)
        self._go = wx.Button(self._panel, label="Send")
        self._go.Bind(wx.EVT_BUTTON, self._on_send)

        self._box.Add(self._input, 0, wx.ALIGN_CENTER)
        self._box.Add(self._go, 0, wx.BOTTOM | wx.ALIGN_CENTER)

        self._box.Layout()

        # self._loop_command = rdcp_command.AltAddr()
        #
        # def loop(r):
        #     print(r)
        #     self._bridge.send_rdcp_command(self._loop_command)
        # self._loop_command.set_handler(loop)
        # self._bridge.send_rdcp_command(self._loop_command)

        # cmd = rdcp_command.AltAddr(handler=lambda r: print(r))
        # cmd = rdcp_command.DriveList(handler=self._on_drive_list)
        # self._bridge.send_rdcp_command(cmd)

        # cmd = rdcp_command.RDCPCommand("capctrla", response_handler=print)
        # cmd.body = b" resp=0q1 name=\"test with\""

        # cmd = rdcp_command.Dbgname(new_name="test_name", handler=print)

        # def thread_list_handler(response):
        #     for thread_id in response.thread_ids:
        #         cmd = rdcp_command.GetContext(thread_id, handler=print)
        #         self._bridge.send_rdcp_command(cmd)
        #
        # cmd = rdcp_command.Threads(handler=thread_list_handler)
        # self._bridge.send_rdcp_command(cmd)

        # cmd = rdcp_command.XBEInfo("e:\\Tools\\boxplorer\\default.xbe", handler=print)
        # self._bridge.send_rdcp_command(cmd)

        cmd = rdcp_command.KernelDebug(
            rdcp_command.KernelDebug.Mode.ENABLE, handler=print
        )
        self._bridge.send_rdcp_command(cmd)

        # cmd = rdcp_command.GetMemBinary(0xB0011360, 128, handler=print)
        # self._bridge.send_rdcp_command(cmd)

    def _on_send(self, evt):
        index = self._input.GetSelection()
        if index < 0:
            return

        command = TEST_COMMANDS[index]

        cmd = rdcp_command.RDCPCommand(
            command, response_handler=self._on_command_response
        )
        self._bridge.send_rdcp_command(cmd)

    def _on_command_response(self, response: rdcp_response.RDCPResponse):
        logging.info(response)
        return False

    def _on_drive_list(self, response: rdcp_command.DriveList.Response):
        logging.info(response)

        cmd = rdcp_command.DriveFreeSpace(
            response.drives[0],
            lambda r: self._on_drive_free_space(response.drives[0], r),
        )
        self._bridge.send_rdcp_command(cmd)
        return False

    def _on_drive_free_space(
        self, drive_letter, response: rdcp_command.DriveFreeSpace.Response
    ):
        logging.info(f"Free space on {drive_letter}: {response}")
        return False
