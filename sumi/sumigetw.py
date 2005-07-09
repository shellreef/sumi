#!/usr/local/bin/python
# Created:2004-07-11
# By Jeff Connelly

# wxWindows GUI interface to sumiget

# Requires wxPython 2.4.2.4 (go to sf.net/projects/wxpython, view all releases)
# NOT wxPython 2.5
from wxPython.wx import *
from wxPython.lib.mixins.listctrl import wxColumnSorterMixin, wxListCtrlAutoWidthMixin
from wxPython.lib.intctrl import *
import sumiget
import thread
import os
import socket

# Modules used by transports; import them  MOVED to sumiget.py
#if sys.platform == 'win32':
#    import win32api
#import irclib
#import mmap

import images

# TCP host and port to receive incoming requests on
# For safety, this is set to localhost. Set host to INADDR_ANY if you want
# to allow requests across the network (not supported by this program).
(REQHOST, REQPORT) = ("localhost", 63538)

# Filename is first column so can use edit column to rename file
COL_FILENAME = 0
COL_PEER = 1
COL_STATUS = 2
COL_PROGRESS = 3
COL_SIZE = 4
COL_BYTES = 5
COL_RATE = 6
COL_FROM = 7
COL_MISSING = 8
COL_REXMITS = 9
COL_ETA = 10
COL_LAST = COL_ETA

ID_EXIT = 100
ID_SETUP = 101

global nick2index, last_index
nick2index = {}
last_index = 0

class MainNotebook(wxNotebook):
    """Tabbed interface."""
    def __init__(self, parent, app):
        wxNotebook.__init__(self, parent, -1, style=wxNB_BOTTOM)

        self.app = app

        self.xfpanel = TransferPanel(self, app)
        self.cfgc = CConfigPanel(self, app)
        self.cfgs = SConfigPanel(self, app)
        self.nets = wxPanel(self, -1)
        self.slog = SLogPanel(self, app)
        self.clog  = CLogPanel(self, app)
        self.exit = wxPanel(self, -1)
        self.AddPage(self.xfpanel, "Transfers")
        self.AddPage(self.cfgc, "Client Setup")
        self.AddPage(self.clog,  "Client Log") 
        self.AddPage(self.cfgs, "Server Setup")
        self.AddPage(self.slog, "Server Log")
        self.AddPage(self.exit, "Exit Now")

        # TODO: design images, assign them here
        # Transfers - cables, data
        # Client - download arrow  \ same as in the
        # Server - upload arrow    / transfers window
        # Networks - ?
        #il = wxImageList(16, 16)
        #idx1 = il.Add(images.getMondrianBitmap())
        #self.AssignImageList(il)
        #self.SetPageImage(0, idx1) 

        EVT_NOTEBOOK_PAGE_CHANGING(self, self.GetId(), self.OnPageChanged)
        self.Show()
        self.ValidateConfig()

    def ValidateConfig(self):
        err = self.app.client.validate_config()
        if err:
            dlg = wxMessageDialog(self.app.frame, err,
                  "Invalid setting", wxOK | wxICON_ERROR);
            dlg.ShowModal()
            #self.SetSelection(1)   # Would be nice if it worked
            return False
        else:
            print "Passed validation"
            return True

    def OnPageChanged(self, event):
        old = event.GetOldSelection()
        new = event.GetSelection()
        sel = self.GetSelection()
 
        print "OnPageChange: ",old,new,sel

        # Use new instead of sel because on Win32, sel is 0 for the first
        # page change, but new is updated correctly
        if (new == self.GetPageCount() - 1):  # Last page = Exit
            self.app.OnCloseFrame()   # save win size
            self.app.OnExit()
            raise SystemExit

        if old == 1:    # Client configuration tab, if change, validate
            if not self.ValidateConfig():
                #event.Veto()  # causes all sorts of problems
                pass

        event.Skip()   #  requires especially on Win32

class SLogPanel(wxPanel):
    """Server log panel."""
    def __init__(self, parent, app):
        wxPanel.__init__(self, parent, -1)
  
        self.app = app
        self.servlog = wxTextCtrl(self, -1, style=wxTE_MULTILINE | wxTE_READONLY)
        box = wxBoxSizer(wxVERTICAL)
        box.Add(self.servlog, 1, wxEXPAND)
        self.SetAutoLayout(true)
        self.SetSizer(box)
        self.Layout()

        self.started = False

        if self.app.client.config["share"]:
            self.start()
        else:
            self.Write("Not starting server--set 'share' to True to enable.\n")

    def start(self):
        """Start sumiserv."""

        self.Write("Starting sumiserv...\n")
        import sumiserv

        def log(msg):
            self.Write(str(msg) + "\n")
        sumiserv.log = log

        thread.start_new_thread(sumiserv.main, ((),))
        self.started = True
        #sumiserv.make_thread(sumiserv.main, (()))

    def Write(self, msg):
        self.servlog.AppendText(msg)

class CLogPanel(wxPanel):
    """Client log output."""
    def __init__(self, parent, app):
        wxPanel.__init__(self, parent, -1)

        self.app = app
        self.textCtrl = wxTextCtrl(self, -1, size=(-1, -1), \
                         style=wxTE_MULTILINE | wxTE_READONLY)
        box = wxBoxSizer(wxVERTICAL)
        box.Add(self.textCtrl, 1, wxEXPAND)
        self.SetAutoLayout(true)
        self.SetSizer(box)
        self.Layout()

        def log(msg):
            if hasattr(self, "Write"):
                self.Write(str(msg) + "\n")
            else:
                print msg
        sumiget.log = log

    def Write(self, msg):
        self.textCtrl.AppendText(msg)

CTL_BANDWIDTH = 500
CTL_CRYPTO = 501
CTL_DCHAN  = 502
CTL_DLDIR  = 503
CTL_BROWSE = 504
CTL_MYIP   = 505
CTL_MYPORT = 506
CTL_MSS    = 507
CTL_TYPE   = 508
CTL_CODE   = 509

class CConfigPanel(wxPanel):
    """Client configuration panel."""
    def __init__(self, parent, app):
        wxPanel.__init__(self, parent, -1, style=wxWANTS_CHARS)

        self.app = app     

        # Layout here is all done manually without sizers

        # Bandwidth in bits per second
        # Load predefined values, sorted descending
        bandwidths = [1000000000, 100000000, 10000000, 1500000, 768000, 384000, 56000, 28000]
        bandwidths.append(self.app.client.config["bandwidth"])
        # Remove duplicates (can use sets in Python 2.4)
        bandwidths = dict.fromkeys(bandwidths).keys()
        bandwidths.sort()
        bandwidths = map(str, bandwidths)
        bandwidths.reverse()

        self.bw_label = wxStaticText(self, -1, "Bandwidth (bps):", \
                                     wxPoint(0, 0), wxSize(-1, -1))
        self.bw = wxComboBox(self, CTL_BANDWIDTH, \
                             str(self.app.client.config["bandwidth"]), \
                             wxPoint(80, 0),
                             wxSize(95, -1),
                             choices=bandwidths, style=wxCB_DROPDOWN)

        EVT_TEXT(self, CTL_BANDWIDTH, self.OnBandwidthChange)

        # Cryptography. TODO: Get pre auth working, then really work on this.
        # Also, make the listbox here one item high. Make it drop down.
        self.crypto_label = wxStaticText(self, -1, "Cryptography:", \
                                wxPoint(0, 30), wxSize(-1, -1))
        self.crypto = wxChoice(self, CTL_CRYPTO, wxPoint(80, 30), wxSize(-1, -1),
                                choices=["None", \
                                         "Symmetric (AES)", \
                                         "Asymmetric", \
                                         "One time pad"])
        self.cryptos = ['', 's', 'a', 'o']
        crypto2n = {'': 0, 's': 1, 'a': 2, 'o': 3}
        self.crypto.SetSelection(crypto2n[self.app.client.config["crypto"]])
        EVT_CHOICE(self, CTL_CRYPTO, self.OnCryptoChange)
        # TODO: Asymmetric encryption key (passwd)

        # Data channel type
        # ICMP here has 2^16 combinations, for each type+code.
        # This is what to do: split "port" into "type" and "code"
        # When ICMP selected, show type&code. When other, show port.
        # Encode as type*0x100+code, thats how sumiserv interprets it.
        self.dchan_label = wxStaticText(self, -1, "Data channel:", \
                                        wxPoint(0, 70), wxSize(-1, -1))
        dchans_rep = ["UDP", "ICMP Direct", "ICMP Echo"]
        #self.dchans_code = ['u', 'e'] + (['?'] * 256)
        self.dchans_code = ['u', 'i', 'e']
        dchan2n = {'u': 0, 'i': 1, 'e': 2}
        #for x in range(0, 256):
        #    dchans_rep.append("ICMP Type=%d Code=0" % x)
        #    dchan2n["i%d,%d" % (x, 0)] = 2 + x
        #    self.dchans_code[x + 2] = "i%d,%d" % (x, 0)
        self.dchan = wxChoice(self, CTL_DCHAN, wxPoint(80, 70), wxSize(-1, -1), 
                                choices=dchans_rep)
        self.dchan.SetSelection(dchan2n[self.app.client.config["data_chan_type"]])
        EVT_CHOICE(self, CTL_DCHAN, self.OnDChanChange)

        # Download directory, [...] common open file dialog
        self.dldir_label = wxStaticText(self, -1, "Download to:", \
                                        wxPoint(0, 110), wxSize(-1, -1))
        self.dldir = wxTextCtrl(self, CTL_DLDIR, self.app.client.config["dl_dir"],
                                wxPoint(80, 110), wxSize(130, -1), \
        # Have to change dldir using browse button, can't edit it directly.
        # Possible but I don't allow this, so validation can be done in the
        # common dialog instead of in user program. 
                                style=wxTE_READONLY)
        self.dldir_browse = wxButton(self, CTL_BROWSE, "...", \
                                     wxPoint(80 + 130, 110), wxSize(20, -1))
        EVT_BUTTON(self, CTL_BROWSE, self.OnDldirBrowse)

        # Send to IP Address ("" = get default IP)
        self.myip_label = wxStaticText(self, -1, "IP Address:", \
                                       wxPoint(250, 0), wxSize(-1, -1))
        myip = self.app.client.config["myip"]
        if len(myip) == 0: myip = "(default)"
        self.myip = wxTextCtrl(self, CTL_MYIP, \
                               myip, \
                               wxPoint(250 + 80, 0), wxSize(-1, -1))
        EVT_TEXT(self, CTL_MYIP, self.OnIPChange)

        # 16-bit (UDP) port, if applicable 
        self.myport_label = wxStaticText(self, -1, "UDP Port:", \
                                         wxPoint(250, 80), wxSize(-1, -1))
        # wxIntCtrl is appealing, but not on Windows? Look into this.
        self.myport = wxIntCtrl(self, CTL_MYPORT, \
                                 self.app.client.config["myport"],
                                 wxPoint(250 + 80, 80), wxSize(-1, -1))
        self.myport.SetMin(0)   # 0 port..heh
        self.myport.SetMax(65535)
        EVT_INT(self, CTL_MYPORT, self.OnPortChange)

        self.myport_label.Show(False)
        self.myport.Show(False)

        self.type_label = wxStaticText(self, -1, "Type:", \
                                       wxPoint(250, 80), wxSize(-1, -1))
        self.type = wxIntCtrl(self, CTL_TYPE, \
                              self.app.client.config["myport"] / 0x100,
                              wxPoint(250 + 40, 80), wxSize(40, -1))

        self.code_label = wxStaticText(self, -1, "Code:", \
                                       wxPoint(250 + 40 + 40, 80), wxSize(-1, -1))

        self.code = wxIntCtrl(self, CTL_CODE, \
                              self.app.client.config["myport"] % 0x100,
                              wxPoint(250 + 40 + 40 + 40, 80), wxSize(40, -1))
        EVT_INT(self, CTL_TYPE, self.OnTypeCodeChange)
        EVT_INT(self, CTL_CODE, self.OnTypeCodeChange)
        self.OnDChanChange()     # Hide/show correct controls

        # MSS. Combo box with common dropdowns, like bandwidth?
        # Only problem is, how do you make combo box only accept ints?
        # Just using an wxIntCtrl for now
        self.mss_label = wxStaticText(self, -1, "MSS:", \
                                      wxPoint(250, 40), wxSize(-1, -1))
        self.mss = wxIntCtrl(self, CTL_MSS, \
                             self.app.client.config["mss"],
                             wxPoint(250 + 80, 40), wxSize(-1, -1))
        EVT_INT(self, CTL_MSS, self.OnMSSChange)

        # TODO: Rwinsz, in seconds. Slider - 1 to 15 or so?
        # TODO: Maxwait, time to wait before handshake. Slider again?
        # Actually, don't need to clutter dialog up with these


    def OnBandwidthChange(self, event):
        bw = event.GetString()
        if len(bw) == 0: return

        self.app.client.config["bandwidth"] = int(bw)

    def OnCryptoChange(self, event):
        self.app.client.config["crypto"] = self.cryptos[event.GetInt()]

    def OnDChanChange(self, event=0):
        if event != 0:
            self.app.client.config["data_chan_type"] = \
                self.dchans_code[event.GetInt()]
        # Show either a 16-bit UDP port or 2 count 8-bit type+code boxes
        show_myport = self.app.client.config["data_chan_type"] == 'u'

        self.myport_label.Show(show_myport)
        self.myport.Show(show_myport)
        self.type_label.Show(not show_myport)
        self.type.Show(not show_myport)
        self.code_label.Show(not show_myport)
        self.code.Show(not show_myport)

        # Keep port and type+code consistant
        self.myport.SetValue(self.app.client.config["myport"])
        self.type.SetValue(self.app.client.config["myport"] / 0x100)
        self.code.SetValue(self.app.client.config["myport"] % 0x100)


    def OnDldirBrowse(self, event):
        # wxDirDialog or wxFileDialog
        # EAC uses wxFileDialog and ignores the filename. I like that idea,
        # because wxDirDialog isn't as good in my opinion.
        
        if (not os.access(self.app.client.config["dl_dir"], os.W_OK | os.X_OK)):
            # Can't read or cd to directory so default to current directory
            self.app.client.config["dl_dir"] = os.getcwd()
        dlg = wxFileDialog(self, "Choose location", \
                  self.app.client.config["dl_dir"], "Filename is ignored",
                  "All files (*.*)|*.*", wxSAVE)
        if dlg.ShowModal() == wxID_OK:
            self.app.client.config["dl_dir"] = os.path.dirname(dlg.GetPath())
            self.dldir.SetValue(self.app.client.config["dl_dir"] + \
                                os.path.sep)

    def OnIPChange(self, event):
        myip = event.GetString()
        if myip == "(default)": myip = ""
        self.app.client.config["myip"] = myip

    def OnPortChange(self, event):
        self.app.client.config["myport"] = event.GetEventObject().GetValue()

    def OnTypeCodeChange(self, event):
        self.app.client.config["myport"] = self.type.GetValue() * 0x100 + self.code.GetValue()

    def OnMSSChange(self, event):
        self.app.client.config["mss"] = event.GetEventObject().GetValue()
 
# This is for mode-less file dialog, but EVT_CLOSE isn't triggered
#        self.browse_dlg.Show()
#        EVT_CLOSE(self.browse_dlg, self.OnDldirBrowseClose)
#
#    def OnDldirBrowseClose(self, event):
#        print "PATH=",self.browse_dlg.GetPath()

# TODO: Server config panel. Server has cooler options than client. :)
# Bind address, or empty for all
# File database - list, with desc, fn, gets, size
# Global mss
# IRC Chans and keywords - list
# IRC Nick
# Server and port
# OTP dir
# Our bandwidth
# Sleep interval, or 0 for no public listings
# Src allow (IP and mask) - suggest subnet of own IP interfaces
# Stealth mode
# IP_TOTLEN_HOST_ORDER

CTL_SHARE = 701

class SConfigPanel(wxPanel):
    """Server configuration panel."""
    def __init__(self, parent, app):
        wxPanel.__init__(self, parent, -1, style=wxWANTS_CHARS)

        self.app = app   
        self.share = wxCheckBox(self, CTL_SHARE, "Enable sharing")
        box = wxBoxSizer(wxVERTICAL)
        box.Add(self.share, 1, wxEXPAND)
        self.SetAutoLayout(true)
        self.SetSizer(box)
        self.Layout()

        self.share.SetValue(self.app.client.config["share"])

        EVT_CHECKBOX(self, CTL_SHARE, self.OnToggleSharing)

    def OnToggleSharing(self, event):
        self.app.client.config["share"] = self.share.GetValue()

        if self.app.client.config["share"] and not self.app.nb.slog.started:
            self.app.nb.slog.start()
        elif not self.app.client.config["share"]:
            # Too annoying?
            #dlg = wxMessageDialog(self.app.frame, 
            #      "The server will be shutdown once sumigetw is restarted.",
            #      "SUMI Server", wxOK | wxICON_INFORMATION);
            #dlg.ShowModal()
            pass

# Somewhat based on wxListCtrl demo
class TransferListCtrl(wxListCtrl, wxListCtrlAutoWidthMixin):
    """List control handling the list of file transfers."""
    def __init__(self, parent, ID, pos=wxDefaultPosition,
                 size=wxDefaultSize, style=0):
        wxListCtrl.__init__(self, parent, ID, pos, size, style)
        wxListCtrlAutoWidthMixin.__init__(self)

class TransferPanel(wxPanel, wxColumnSorterMixin):
    """Panel encapsulating the list transfer control."""
    def __init__(self, parent, app):
        wxPanel.__init__(self, parent, -1, style=wxWANTS_CHARS)
                                                 #wxTAB_TRAVERSAL)
        # TODO: Column sorting is disabled now because nick2index loses
        # its associations and starts writing to the wrong column.
        #wxColumnSorterMixin.__init__(self, 3)

        tID = wxNewId()

        self.il = wxImageList(16, 16)

        self.app = app

        self.idx1 = self.il.Add(images.getSmilesBitmap())
        self.sm_up = self.il.Add(images.getSmallUpArrowBitmap())
        self.sm_dn = self.il.Add(images.getSmallDnArrowBitmap())

        self.list = TransferListCtrl(self, tID,
                                 style=wxLC_REPORT #| wxSUNKEN_BORDER
                                 | wxLC_EDIT_LABELS
                                 #| wxLC_VRULES | wxLC_HRULES
                                 | wxLC_HRULES, 
                                 size=(100,100), pos=(50,50))
        self.list.SetImageList(self.il, wxIMAGE_LIST_SMALL)

        self.itemDataMap = {}

        self.SetupList()


        # XXX: These are left over from wxListCtrl demo. 
        # TODO: Do something useful with them
        EVT_SIZE(self, self.OnSize)
        EVT_LIST_ITEM_SELECTED(self, tID, self.OnItemSelected)
        EVT_LIST_ITEM_DESELECTED(self, tID, self.OnItemDeselected)
        EVT_LIST_ITEM_ACTIVATED(self, tID, self.OnItemActivated)
        EVT_LIST_DELETE_ITEM(self, tID, self.OnItemDelete)
        EVT_LIST_COL_CLICK(self, tID, self.OnColClick)
        EVT_LIST_COL_RIGHT_CLICK(self, tID, self.OnColRightClick)
        EVT_LIST_COL_BEGIN_DRAG(self, tID, self.OnColBeginDrag)
        EVT_LIST_COL_DRAGGING(self, tID, self.OnColDragging)
        EVT_LIST_COL_END_DRAG(self, tID, self.OnColEndDrag)
        # Begin and end rename
        EVT_LIST_BEGIN_LABEL_EDIT(self, tID, self.OnBeginEdit)
        EVT_LIST_END_LABEL_EDIT(self, tID, self.OnEndEdit)

        EVT_LEFT_DCLICK(self.list, self.OnDoubleClick)
        EVT_RIGHT_DOWN(self.list, self.OnRightDown)

        # for wxMSW
        EVT_COMMAND_RIGHT_CLICK(self.list, tID, self.OnRightClick)

        # for wxGTK
        EVT_RIGHT_UP(self.list, self.OnRightClick)

    def SetupList(self):
        """Sets up the columns of the transfer list control."""
        info = wxListItem()
        info.m_mask = wxLIST_MASK_TEXT | wxLIST_MASK_IMAGE | wxLIST_MASK_FORMAT
        info.m_image = -1
        info.m_format = 0

        colnames = ['Filename', 'Peer', 'Status', 'Progress', 'Size', \
                    'Bytes', 'Rate', 'From', 
                    'Missing', 'Rexmits', 'ETA']
        colfmt = [0, 0, 0, wxLIST_FORMAT_RIGHT, wxLIST_FORMAT_RIGHT, \
                  wxLIST_FORMAT_RIGHT, wxLIST_FORMAT_RIGHT, \
                  wxLIST_FORMAT_RIGHT, wxLIST_FORMAT_RIGHT, \
                  wxLIST_FORMAT_RIGHT, 0, wxLIST_FORMAT_RIGHT ]

        for x in range(0, COL_LAST + 1):
            info.m_text = colnames[x]
            info.m_format = colfmt[x]
            self.list.InsertColumnInfo(x, info)

        items = self.itemDataMap.items()
        for x in range(len(items)):
            key, data = items[x]
            self.list.InsertImageStringItem(x, data[0], self.sm_dn)
            for n in range(1, len(data)):
                self.list.SetStringItem(x, n, data[n])
            self.list.SetItemData(x, key)

        # Autosize the columns
        #for x in range(0, COL_LAST):
        #    self.list.SetColumnWidth(x, wxLIST_AUTOSIZE)

        # This is neat, column widths are saved and restored so they are always
        # exactly as you (user) left them. No autosize to worry about.
        colno = 0
        for x in self.app.client.config["colwidths"]:
            self.list.SetColumnWidth(colno, x)
            colno += 1
        #self.list.SetColumnWidth(0, 100)

        self.currentItem = 0

    # Used by the wxColumnSorterMixin, see wxPython/lib/mixins/listctrl.py
    def GetListCtrl(self):
        return self.list

    # Used by the wxColumnSorterMixin, see wxPython/lib/mixins/listctrl.py
    def GetSortImages(self):
        # These are the icons that appear for ascending/descending sorting
        return (self.sm_dn, self.sm_up)

    # Right click
    def OnRightDown(self, event):
        self.x = event.GetX()
        self.y = event.GetY()
        print "x, y = %s\n" % str((self.x, self.y))
        item, flags = self.list.HitTest((self.x, self.y))
        if flags & wxLIST_HITTEST_ONITEM:
            self.list.Select(item)
        event.Skip()


    def getColumnText(self, index, col):
        item = self.list.GetItem(index, col)
        return item.GetText()

    # An item was selected
    def OnItemSelected(self, event):
        ##print event.GetItem().GetTextColour()
        self.currentItem = event.m_itemIndex
        print "OnItemSelected: %s, %s, %s, %s\n" % \
                           (self.currentItem,
                            self.list.GetItemText(self.currentItem),
                            self.getColumnText(self.currentItem, 1),
                            self.getColumnText(self.currentItem, 2))
        # Able to prevent item from being selected, if needed
        #if self.currentItem == 10:
        #    print "OnItemSelected: Veto'd selection\n"
        #    #event.Veto()  # doesn't work
        #    # this does
        #    self.list.SetItemState(10, 0, wxLIST_STATE_SELECTED)
        event.Skip()


    # An item was deselected
    def OnItemDeselected(self, evt):
        item = evt.GetItem()
        print "OnItemDeselected: %d" % evt.m_itemIndex

        # Show how to reselect something we don't want deselected
        #if evt.m_itemIndex == 11:
        #    wxCallAfter(self.list.SetItemState, 11, wxLIST_STATE_SELECTED, wxLIST_STATE_SELECTED)


    def OnItemActivated(self, event):
        self.currentItem = event.m_itemIndex
        print "OnItemActivated: %s\nTopItem: %s" % \
                           (self.list.GetItemText(self.currentItem), self.list.GetTopItem())

    # Edits the first field--the filename. 
    # On-the-fly filename renaming during transfer. Unix supports this.
    # MSW might not, due to permissions.
    def OnBeginEdit(self, event):
        self.rename_from = event.GetText()
        #print "OnBeginEdit, ", self.rename_from
        event.Allow()

    def OnEndEdit(self, event):
        #print "OnEndEdit"
        fr = self.rename_from
        to = event.GetText()
        print "Renaming %s->%s" % (fr, to)
        os.rename(self.app.client.config["dl_dir"] + fr,
                  self.app.client.config["dl_dir"] + to)
        os.rename(self.app.client.config["dl_dir"] + fr + ".lost",
                  self.app.client.config["dl_dir"] + to + ".lost")

    # Deleting an item.. TODO: cancel transfer
    def OnItemDelete(self, event):
        print "OnItemDelete\n"

    # Column click. This usually sorts by that column
    # TODO: Keep track of nick2index, because the indexes change
    # Right now, autosorting by column clicking is disabled
    def OnColClick(self, event):
        print "OnColClick: %d\n" % event.GetColumn()

    # Right-clicking a column
    def OnColRightClick(self, event):
        item = self.list.GetColumn(event.GetColumn())
        print "OnColRightClick: %d %s\n" % \
                           (event.GetColumn(), (item.GetText(), item.GetAlign(),
                                                item.GetWidth(), item.GetImage()))

    # Dragging a column
    def OnColBeginDrag(self, event):
        print "OnColBeginDrag\n"
        ## Show how to not allow a column to be resized
        #if event.GetColumn() == 0:
        #    event.Veto()


    def OnColDragging(self, event):
        print "OnColDragging\n"

    def OnColEndDrag(self, event):
        # Save new column width in config, then 
        # save config to config.py, like with sumiserv
        w = [0] * COL_LAST
        for x in range(0, COL_LAST):
            w[x] = self.list.GetColumnWidth(x)
        self.app.client.config["colwidths"] = w
        print "Set widths to ",w       
 
        print "OnColEndDrag\n"

    # Double-clicking a column..no real use
    def OnDoubleClick(self, event):
        print "OnDoubleClick item %s\n" % self.list.GetItemText(self.currentItem)
        #self.list.InsertImageStringItem(0, "hi", self.sm_dn)
        event.Skip()

    # Right-click item context menu, transfer-specific functions
    def OnRightClick(self, event):
        print "OnRightClick %s\n" % self.list.GetItemText(self.currentItem)

        # only do this part the first time so the events are only bound once
        if not hasattr(self, "popupID1"):
            self.popup_open = wxNewId()
            self.popup_opendir = wxNewId()
            self.popup_abort = wxNewId()
            self.popup_resume = wxNewId()
            self.popup_rename = wxNewId()
            #self.popupID1 = wxNewId()
            #self.popupID2 = wxNewId()
            #self.popupID3 = wxNewId()
            #self.popupID4 = wxNewId()
            #self.popupID5 = wxNewId()
            #self.popupID6 = wxNewId()
            EVT_MENU(self, self.popup_open, self.OnOpen)
            EVT_MENU(self, self.popup_opendir, self.OnOpenDir)
            EVT_MENU(self, self.popup_abort, self.OnAbort)
            EVT_MENU(self, self.popup_resume, self.OnResume)
            EVT_MENU(self, self.popup_rename, self.OnRename)
            #EVT_MENU(self, self.popupID1, self.OnPopupOne)
            #EVT_MENU(self, self.popupID2, self.OnPopupAbort)
            #EVT_MENU(self, self.popupID3, self.OnPopupThree)
            #EVT_MENU(self, self.popupID4, self.OnPopupFour)
            #EVT_MENU(self, self.popupID5, self.OnPopupFive)
            #EVT_MENU(self, self.popupID6, self.OnPopupSix)

        # make a menu
        menu = wxMenu()
        # add some items
        menu.Append(self.popup_open, "Open")
        menu.Append(self.popup_opendir, "Open Folder")
        menu.Append(self.popup_abort, "Abort")
        menu.Append(self.popup_resume, "Resume")
        menu.Append(self.popup_rename, "Rename")
        #menu.Append(self.popupID1, "FindItem tests")
        #menu.Append(self.popupID2, "Abort Selected")
        #menu.Append(self.popupID3, "ClearAll and repopulate")
        #menu.Append(self.popupID4, "DeleteAllItems")
        #menu.Append(self.popupID5, "GetItem")
        #menu.Append(self.popupID6, "Edit")

        # Popup the menu.  If an item is selected then its handler
        # will be called before PopupMenu returns.
        self.PopupMenu(menu, wxPoint(self.x, self.y))
        menu.Destroy()

    def OnOpen(self, event):
        print "Opening selected file..."
        f = self.list.GetItemText(self.currentItem)
        print f
        os.startfile(self.app.client.config["dl_dir"] + os.path.sep + f)

    def OnOpenDir(self, event):
        print "TODO: Open containing directory"
        os.startfile(self.app.client.config["dl_dir"])

    def OnAbort(self, event):
        print "Selected items:\n"
        index = self.list.GetFirstSelected()
        while index != -1:
            print "      %s: %s\n" % (self.list.GetItemText(index), self.getColumnText(index, 1))
            # TODO: Separate nick into its own column, seriously
            snick = self.getColumnText(index, 1).split(" ")
            if len(snick) >= 1:
                snick = snick[0]
            else:
                continue
            self.app.client.abort(snick)
            index = self.list.GetNextSelected(index)
    
    def OnResume(self, event): 
        #self.app.client.resume...
        print "TODO: Resume"

    def OnRename(self, event):
        self.list.EditLabel(self.currentItem)
        print "TODO: Rename file"

    # Examples
    def OnPopupOne(self, event):
        print "Popup one\n"
        print "FindItem:", self.list.FindItem(-1, "Roxette")
        print "FindItemData:", self.list.FindItemData(-1, 11)

    def OnPopupThree(self, event):
        print "Popup three\n"
        self.list.ClearAll()
        wxCallAfter(self.SetupList)

    def OnPopupFour(self, event):
        self.list.DeleteAllItems()

    def OnPopupFive(self, event):
        item = self.list.GetItem(self.currentItem)
        print item.m_text, item.m_itemId, self.list.GetItemData(self.currentItem)

    def OnPopupSix(self, event):
        self.list.EditLabel(self.currentItem)


    def OnSize(self, event):
        w,h = self.GetClientSizeTuple()
        self.list.SetDimensions(0, 0, w, h)

# SUMI application
class SUMIApp(wx.wxApp):
    def __init__(self):
        print "__init__"
        wx.wxApp.__init__(self, 0)
        print "__init__ 2"

    def OnInit(self):
        print "OnInit"
        # Setup receive requests thread/send requests. Do this first because
        # it might be the last thing we do.
        self.RecvReq()

        self.client = sumiget.Client()

        wx.wxInitAllImageHandlers()

        # Frame to hold the notebook
        self.frame = wx.wxFrame(None, -1, "SUMI", pos=(50,50), 
                        style=wx.wxNO_FULL_REPAINT_ON_RESIZE|wx.wxDEFAULT_FRAME_STYLE|wxTAB_TRAVERSAL)

        self.frame.icon = wxIcon("sumi.ico", wxBITMAP_TYPE_ICO)
        if self.frame.icon:
            self.frame.SetIcon(self.frame.icon)
        else:
            print "failed to set icon"

        #self.frame.CreateStatusBar()
        self.nb = MainNotebook(self.frame, self)

        # No menubar
        #menuBar = wx.wxMenuBar()
        #menu = wx.wxMenu()
        #menu.Append(101, "E&xit\tAlt-X", "Exit demo")
        #wx.EVT_MENU(self, 101, self.OnExit)
        #menuBar.Append(menu, "&File")
        #self.frame.SetMenuBar(menuBar)

        wx.EVT_CLOSE(self.frame, self.OnCloseFrame)

        # This is all commented out because we use a wxNotebook now
        #self.xfpanel = TransferPanel(self.frame, self)
        #self.setup = wxButton(self.frame, ID_SETUP, "&Setup")
        #self.exit = wxButton(self.frame, ID_EXIT, "E&xit")
        #btns = wxBoxSizer(wxHORIZONTAL)
        #box = wxBoxSizer(wxVERTICAL)
        #box.Add(self.xfpanel, 5, wxEXPAND)  # Button proportion
        #box.Add(btns, 1, wxEXPAND)
        ## Row of buttons
        #btns.Add(self.setup, 1, wxEXPAND)
        #btns.Add(self.exit, 1, wxEXPAND)
        #self.frame.SetAutoLayout(true)
        #self.frame.SetSizer(box)
        #self.frame.Layout()

        #EVT_BUTTON(self.exit, ID_EXIT, self.OnExit)
        #EVT_BUTTON(self.setup, ID_SETUP, self.OnSetup)

        # Setup the SUMI 
        # Only really need one of these each per transfer
        thread.start_new_thread(self.client.thread_timer, ())
        thread.start_new_thread(self.client.thread_recv_packets, ())
   
        print "Sys args=", sys.argv 
        thread.start_new_thread(self.ReqThread, (sys.argv[1], sys.argv[2], sys.argv[3]))

        # For IPC
        # As of 20040712, this is no longer needed! Uses sockets.
        #if (sys.platform == 'win32'):
        ## Note: this is wrong, GetHandle is supposed to be applied to the wnd
        #    sumiget.save_pid(self.GetHandle())
        #else:
        #    sumiget.save_pid(os.getpid())

        self.frame.Show(True)
        # Restore saved window size
        self.frame.SetSize(self.client.config["winsize"])

        # Note; xfpanel size isn't set/retreived ever - only window size
        #self.xfpanel.SetSize(self.client.config["winsize"])

        self.nb.xfpanel.SetFocus()

        self.SetTopWindow(self.frame)
        return True

    def RecvReq(self):
        """Sets up the request receiving, passes to an existing instance 
           if there is one, otherwise listens for commands using RecvReqThread.
        
           This is used to allow one sumigetw instance to handle multiple
           requests, not serving."""
        ss = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            ss.bind((REQHOST, REQPORT))
        except socket.error:
            # Most likely (48, 'Address already in use')
            # This means we're already running. Send command to ourself.
            print "Sending command to existing instance"
            ss.connect((REQHOST, REQPORT))
            ss.send(sys.argv[1] + "\t" + sys.argv[2] + "\t" + sys.argv[3])
            ss.close()
            sys.exit(0)
            # If this code is ran (above) but another instance is not
            # running, then REQPORT is in use by someone else. Change REQPORT.
        ss.listen(5)
        thread.start_new_thread(self.RecvReqThread, (ss, ))

    def RecvReqThread(self, ss):
        """Thread that receives socket connections in order to handle 
            additional requests after the program is started."""
        while 1:
            (cs, addr) = ss.accept()
            data = cs.recv(256)
            (transport, nick, fn) = data.split("\t")
            print "Received req from",addr,"=",data
            thread.start_new_thread(self.ReqThread, (transport, nick, fn))

    def ReqThread(self, transport, nick, filename):
        """Thread that handles a request."""
        global nick2index, last_index

        self.client.set_callback(self.Callback)

        # nick2index associates the nickname with the location in the listbox
        # TODO: Use transfer key instead, as its unique. Then might be able to
        # do multiple transfers per nick
        if nick2index.has_key(nick):
            index = nick2index[nick]
            if self.nb.xfpanel.getColumnText(index, COL_STATUS) == 'Transferring...':
                print "ERROR: In-progress transfer from",nick,"at",index,"already"
                print "Currently you can only have one transfer per user, sorry"
                return 
        else:
            nick2index[nick] = last_index
            index = nick2index[nick]
            last_index += 1

        print "Inserting at index",index
        self.nb.xfpanel.list.InsertImageStringItem(index, nick, self.nb.xfpanel.sm_dn)
        self.nb.xfpanel.itemDataMap[index] = [0] * (COL_LAST + 1)
        self.SetInfo(nick, COL_FILENAME, filename)
        self.SetInfo(nick, COL_PEER, nick)
        self.SetInfo(nick, COL_STATUS, "Requesting")
        #self.SizeCols()
        # Will return -1 if fails immediately, 0 if success. But we also
        # get callback messages, so set the error status there.
        self.client.request(transport, nick, filename)

        # End of thread

    def SizeCols(self):
        """Autosize the columns."""
        # No, don't call this. Instead use widths from config file
        for x in range(0, COL_LAST):
            self.nb.xfpanel.list.SetColumnWidth(x, wxLIST_AUTOSIZE)


    def SetColor(self, nick, c):
        """Sets the color of a row."""
        item = self.nb.xfpanel.list.GetItem(nick2index[nick])
        item.SetTextColour(c)
        self.nb.xfpanel.list.SetItem(item)

    def SetInfo(self, nick, field, data):
        """Sets a field in the transfer list."""
        self.nb.xfpanel.list.SetStringItem(nick2index[nick], field, data)
        self.nb.xfpanel.itemDataMap[nick2index[nick]][field] = data
        # commented out, resize manually if needed
        #self.SizeCols()  # resizing on every SetInfo might be too excessive

    def Callback(self, nick, cmd, *args):
        """Called by sumiget module when something happens."""
        # BUG: "nick" is all that uniquely identifies the transfer, so 
        # multiple transfers with same users is not yet supported. Could the
        # prefix be used to identify the columns instead? As of now, multiple
        # entries with same nick will always refer to the first with that nick.
        if (cmd == "aborting"):   # aborting in progress
            self.SetInfo(nick, COL_STATUS, "Aborting...")
            # TODO: Stop request thread? It still sends acks...
        elif (cmd == "t_wait"):   # waiting for transport
            self.SetInfo(nick, COL_STATUS, "Transport loading")
        elif (cmd == "1xferonly"):  # transfer already in progress
            self.SetInfo(nick, COL_STATUS, "Another transfer in progress")
            self.SetColor(nick, wxRED)  # Maybe queue it instead?
        elif (cmd == "t_fail"): # transport failed to load
            msg = args[0][1].args[0]
            self.SetInfo(nick, COL_STATUS, "Bad transport: %s" % msg)
            self.SetColor(nick, wxRED)
        elif (cmd == "req_sent"):  # request was sent
            self.SetInfo(nick, COL_STATUS, "Handshaking")
        elif (cmd == "req_count"): # request handshake countdown
            self.SetInfo(nick, COL_STATUS, "Handshaking (%d)" % args[0])
        elif (cmd == "rexmits"):   # retransmission
            self.SetInfo(nick, COL_REXMITS, str(args[0]))
        elif (cmd == "lost"):      # outstanding lost packets
            self.SetInfo(nick, COL_MISSING, str(len(args[0])))
        elif (cmd == "dec"):       # decrypting in progress
            self.SetInfo(nick, COL_STATUS, "Decrypt %s" % args[0])
        elif (cmd == "timeout"):   # timed out/no such nick
            self.SetInfo(nick, COL_STATUS, "Timeout")
            self.SetColor(nick, wxRED)
        elif (cmd == "info"):   # sent on reception of auth packet, ready
            (size, prefix, filename, transport, dchantype) = args
            print "Info: ", args

            # Like xchat's dcc, blue=transferring, green=done, & red=err
            self.SetColor(nick, wxBLUE)
            self.SetInfo(nick, COL_STATUS, "Transferring...")
            self.SetInfo(nick, COL_FILENAME, filename)
            self.SetInfo(nick, COL_SIZE, "%d" % size)
            self.SetInfo(nick, COL_BYTES, "0")
            self.SetInfo(nick, COL_PEER, "%s [%s-%s-%s]" % \
                (nick, prefix, transport, dchantype))

            # can't set range to file size because multiples of 1048576
            # do not show up, at any SetValue(), in Win32 only
            #self.gauge.SetRange(10000)  #args[0])
            self.filename = filename
        elif (cmd == "rate"):   # update rate of transfer
            (rate, eta) = args
            self.SetInfo(nick, COL_RATE, "%.1fKB/s" % (rate / 1024))
            self.SetInfo(nick, COL_ETA, "%d min" % int(eta / 60))
        elif (cmd == "write"):
            #self.gauge.SetValue(int(args[1]))
            # XXX Is this correct? Lost packets? Will overestimate.
            #    % done = (total size of pcks recvd) / (file size) * 100
            # Always round down (to ceiling) when calculating file progress
            # so the percentage reaches 100% only when completely done!
            #self.gauge.SetValue(int(args[1] * 10000. / args[3]))
            # ARGS = pktstart, pktend, pktlength, totlen
            #         ^ file offsets ^   MSS     size
            #self.info.SetLabel("Transferring... %.3f%% from %s" % \
            #    (args[1] * 100. / args[3], args[4][0]))
            #self.SetInfo(nick, COL_PROGRESS, "%.3f%%" % \
            #             (args[1] * 100. / args[3]))

            # New write args: offset, n_received_bytes, total_size
            (offset, bytes, size, addr) = args
            self.SetInfo(nick, COL_BYTES, str(bytes))
            percent = "%.1f%%" % (bytes * 100. / size)
            # When done, drop trailing floating point to accommodate the
            # length of '100' compared to anything less. Minor cosmetic.
            if (percent == "100.0%"): percent = "100%"

            #self.SetInfo(nick, COL_PROGRESS, "%.1f%%" % \
            #    (bytes * 100. / size))
            self.SetInfo(nick, COL_PROGRESS, percent)
            # IP:Port
            #self.SetInfo(nick, COL_FROM, ":".join(map(str, addr)))
            # just IP - I like this one better
            self.SetInfo(nick, COL_FROM, addr[0])
        elif (cmd == "fin"):
            (duration, size, speed, all_lost) = args
            self.SetInfo(nick, COL_STATUS, "Complete")
            self.SetInfo(nick, COL_RATE, "%d" % speed)
            self.SetColor(nick, wxColour(32, 128, 32))   # a suitable green
            #self.info.SetLabel("Complete %d B @ %d kB/s: %s" % \
            #    (size, speed, all_lost))

    def OnExit(self, evt=0):
        # If closed by "X" button on Win32, self.frame will already be
        # destroyed, so don't destroy it. But if closed programatically,
        # (by calling us--OnExit), then self.frame needs to be destroyed.
        if (self.frame): self.frame.Close(True)

        self.client.on_exit()   # Save client config
        sys.exit(0)

    def OnCloseFrame(self, evt=0):
        # Save size of *frame* (not xfpanel) before the frame closes
        # (Has to be done here, not in OnExit because already closed by then)
        self.client.config["winsize"] = self.frame.GetSizeTuple()
        if (evt != 0): evt.Skip()

def main(argv):
    if (len(sys.argv) < 4):
        print "Usage: %s transport nick fn" % sys.argv[0]
        #sys.argv = ['fake'] * 4
        sys.argv = ['sumigetw', 'fake', 'no_user', 'no_file']
        #return

    print "Loading app..."
    app = SUMIApp()
    print "Running main loop"
    app.MainLoop()

if __name__ == "__main__":
    main(sys.argv)


