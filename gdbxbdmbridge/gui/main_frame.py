import wx
import wx.grid
import wx.lib.newevent

from gdbxbdmbridge import bridge_info

LaunchXBDMBrowserEvent, EVT_LAUNCH_XBDM_BROWSER = wx.lib.newevent.NewCommandEvent()


class MainFrame(wx.Frame):
    """Main window"""

    LaunchXBDMBrowserEvent = LaunchXBDMBrowserEvent
    EVT_LAUNCH_XBDM_BROWSER = EVT_LAUNCH_XBDM_BROWSER

    def __init__(self, title: str, *args, **kw):
        super().__init__(*args, parent=None, title=title, **kw)

        self.xbdm_table = _XBDMGrid(self)

    def set_discovered_devices(self, discovered_devices: [bridge_info.BridgeInfo]):
        self.xbdm_table.set_rows(sorted(discovered_devices, key=lambda x: x[1]))


class _XBDMGrid(wx.grid.Grid):
    def __init__(self, parent, *args, **kw):
        super().__init__(*args, parent=parent, **kw)

        self.CreateGrid(0, 3)
        self.SetSelectionMode(wx.grid.Grid.GridSelectRows)
        self.EnableEditing(False)
        self.DisableDragColMove()
        self.DisableDragRowSize()
        self.HideRowLabels()

        # Disable rendering of selected cell.
        self.SetCellHighlightPenWidth(0)
        self.SetCellHighlightROPenWidth(0)

        self.SetColLabelValue(0, "Name")
        self.SetColLabelValue(1, "XBOX Address")
        self.SetColLabelValue(2, "GDB Address")

        self.AutoSizeColumns()

        self.Bind(wx.grid.EVT_GRID_CELL_LEFT_DCLICK, self.OnCellLeftDClick)

    def set_rows(self, rows: [bridge_info.BridgeInfo]):
        self.ClearGrid()
        self.InsertRows(numRows=len(rows))

        for row_index in range(0, len(rows)):
            row = rows[row_index]
            self.SetCellValue(row_index, 0, row.xbox_name)
            self.SetCellValue(row_index, 1, f"{row.xbox_addr[0]}:{row.xbox_addr[1]}")
            listen_ip = row.listen_addr[0]
            if listen_ip == "0.0.0.0":
                listen_ip = ""
            self.SetCellValue(row_index, 2, f"{listen_ip}:{row.listen_addr[1]}")

        self.AutoSize()

    def OnCellLeftDClick(self, evt):
        row = evt.GetRow()
        # Convert the address string back into the socket addr.
        addr = self.GetCellValue(row, 1).split(":")
        addr[1] = int(addr[1])
        new_event = LaunchXBDMBrowserEvent(
            evt.GetEventObject().GetId(), addr=tuple(addr)
        )
        wx.PostEvent(self, new_event)
        evt.Skip()
