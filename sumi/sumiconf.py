#!/usr/local/bin/python
# Created:2004-09-07
# By Jeff Connelly

# wxWindows GUI interface to configure sumiserv

# Requires wxPython 2.4.2.4 (go to sf.net/projects/wxpython, view all releases)
# NOT wxPython 2.5
from wxPython.wx import *
from wxPython.lib.mixins.listctrl import wxColumnSorterMixin, wxListCtrlAutoWidthMixin
from wxPython.lib.intctrl import *

class ConfDialog(wxDialog):
    def __init__(self, parent, ID, title,
                 pos=wxDefaultPosition, size=wxDefaultSize,
                 style=wxDEFAULT_DIALOG_STYLE):

        pre = wxPreDialog()
        pre.SetExtraStyle(wxDIALOG_EX_CONTEXTHELP)
        pre.Create(parent, ID, title, pos, size, style)

        self.this = pre.this

        sizer = wxBoxSizer(wxVERITCAL)
        label = wxStaticText(self, -1, "sumiserv conf tool")
        label.SetHelpText("Help text here")
        sizer.Add(label, 0, wxALIGN_CENTER|wxALL, 5)

        box = wxBoxSizer(wxHORIZONTAL)
        text = wxTextCtrl(self, -1, "", size=(80,-1))
        box.Add(text, 1, wxALIGN_CENTER|wxALL, 5)

        sizer.AddSizer(box, 0, wxGROW|wxALIGN_CENTER_VERTICAL|wxALL, 5)

        self.SetSizer(sizer)
        self.SetAutoLayout(True)
        sizer.Fit(self)

class ConfApp(wx.wxApp):
    def __init__(self):
        wx.wxApp.__init__(self, 0)

    def OnInit(self):
        self.dlg = wxDialog(None, -1, "SUMI Server Configuration") 

        return True

def main(argv):
    app = ConfApp()
    app.MainLoop()

if __name__ == "__main__":
    main(sys.argv)
 
