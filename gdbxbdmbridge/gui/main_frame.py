import wx
import wx.grid
import wx.lib.newevent

LaunchXBDMBrowserEvent, EVT_LAUNCH_XBDM_BROWSER = wx.lib.newevent.NewCommandEvent()


class MainFrame(wx.Frame):
    """Main window"""

    LaunchXBDMBrowserEvent = LaunchXBDMBrowserEvent
    EVT_LAUNCH_XBDM_BROWSER = EVT_LAUNCH_XBDM_BROWSER

    def __init__(self, title: str, *args, **kw):
        super().__init__(*args, parent=None, title=title, **kw)

        self.xbdm_table = _XBDMGrid(self)

    def set_discovered_devices(self, discovered_devices: [((str, int), str)]):
        self.xbdm_table.set_rows(sorted(discovered_devices, key=lambda x: x[1]))


class _XBDMGrid(wx.grid.Grid):
    def __init__(self, parent, *args, **kw):
        super().__init__(*args, parent=parent, **kw)

        self.CreateGrid(0, 2)
        self.SetSelectionMode(wx.grid.Grid.GridSelectRows)
        self.EnableEditing(False)
        self.DisableDragColMove()
        self.DisableDragRowSize()
        self.HideRowLabels()

        # Disable rendering of selected cell.
        self.SetCellHighlightPenWidth(0)
        self.SetCellHighlightROPenWidth(0)

        self.SetColLabelValue(0, "Name")
        self.SetColLabelValue(1, "Address")

        self.SetColMinimalAcceptableWidth(120)
        self.SetColMinimalWidth(0, 120)
        self.AutoSizeColumns()

        self.Bind(wx.grid.EVT_GRID_CELL_LEFT_DCLICK, self.OnCellLeftDClick)

    def set_rows(self, rows: [((str, int), str)]):
        self.ClearGrid()
        self.InsertRows(numRows=len(rows))

        for row_index in range(0, len(rows)):
            row = rows[row_index]
            self.SetCellValue(row_index, 0, row[1])
            self.SetCellValue(row_index, 1, f"{row[0][0]}:{row[0][1]}")

        self.AutoSize()

    def OnCellLeftDClick(self, evt):
        row = evt.GetRow()
        addr = self.GetCellValue(row, 1)
        new_event = LaunchXBDMBrowserEvent(evt.GetEventObject().GetId(), addr=addr)
        wx.PostEvent(self, new_event)
        evt.Skip()
