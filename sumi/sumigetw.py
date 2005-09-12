#!/usr/local/bin/python
# Created:2004-07-11
# By Jeff Connelly

# $Id$

# wxWidgets GUI interface to sumiget
# Copyright (C) 2004-2005  Jeff Connelly

# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
# 
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, 
# USA, or online at http://www.gnu.org/copyleft/gpl.txt .



import sumiget
import thread
import os
import socket
import sys
import time

from libsumi import *

# Used to require wxPython 2.4.2.4 (sf.net/projects/wxpython, view all releases)
# But now uses wxPython 2.6.1.0

#from wxPython.wx import *
#from wxPython.lib.mixins.listctrl import wxColumnSorterMixin, wxListCtrlAutoWidthMixin
#from wxPython.lib.intctrl import *

import wx
assert wx.VERSION >= (2,6,0,0,''), \
        ("You need at least wxPython 2.6.0.0, but you have %s.\n"
        "Please upgrade at http://www.wxpython.org/") % (
                ".".join(map(str, wx.VERSION)))

from wx.lib.mixins.listctrl import ColumnSorterMixin, ListCtrlAutoWidthMixin
from wx.lib.intctrl import IntCtrl, EVT_INT

# TCP host and port to receive incoming requests on
# For safety, this is set to localhost. Set host to INADDR_ANY if you want
# to allow requests across the network (not supported by this program).
(REQHOST, REQPORT) = ("localhost", 63538)

# Filename is first column so can use edit column to rename file
COL_FILENAME = 0
COL_PEER = 1
COL_PREFIX = 2
COL_VIA = 3
COL_STATUS = 4
COL_PROGRESS = 5
COL_SIZE = 6
COL_BYTES = 7
COL_RATE = 8
COL_FROM = 9
COL_MISSING = 10
COL_REXMITS = 11
COL_ETA = 12
COL_LAST = COL_ETA

ID_EXIT = 100
ID_SETUP = 101

global nick2index, last_index
nick2index = {}
last_index = 0

class MainNotebook(wx.Notebook):
    """Tabbed interface."""
    def __init__(self, parent, app):
        wx.Notebook.__init__(self, parent, -1, style=wx.NB_BOTTOM)

        self.app = app

        # Validate config before config panel is created (may change conf)
        self.ValidateConfig()

        self.xfpanel = TransferPanel(self, app)
        self.cfgc = CConfigPanel(self, app)
        self.cfgs = SConfigPanel(self, app)
        self.nets = wx.Panel(self, -1)
        self.slog = SLogPanel(self, app)
        self.clog  = CLogPanel(self, app)
        self.exit = ExitPanel(self, app)
        self.AddPage(self.xfpanel, "Transfers")
        self.AddPage(self.cfgc, "Client Setup")
        self.AddPage(self.clog,  "Client Log") 
        self.AddPage(self.cfgs, "Server Setup")
        self.AddPage(self.slog, "Server Log")
        self.AddPage(self.exit, "Save and Exit")

        # TODO: design images, assign them here
        # Transfers - cables, data
        # Client - download arrow  \ same as in the
        # Server - upload arrow    / transfers window
        # Networks - ?
        #il = wx.ImageList(16, 16)
        #idx1 = il.Add(images.getMondrianBitmap())
        #self.AssignImageList(il)
        #self.SetPageImage(0, idx1) 

        wx.EVT_NOTEBOOK_PAGE_CHANGING(self, self.GetId(), self.OnPageChanged)
        self.Show()

    def ValidateConfig(self):
        err = self.app.client.validate_config()
        # TODO: after config is validated, update config widgets!
        if err:
            # This is quite annoying, could it be placed somewhere else?
            dlg = wx.MessageDialog(self.app.frame, err,
                  "Invalid setting", wx.OK | wx.ICON_ERROR);
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

        if old == 1:    # Client configuration tab, if change, validate
            if not self.ValidateConfig():
                # Used to cause problems, but doesn't seem to now
                event.Veto()
                pass

        event.Skip()   #  requires especially on Win32

class CLogPanel(wx.Panel):
    """Client log output."""
    def __init__(self, parent, app):
        wx.Panel.__init__(self, parent, -1)

        self.clogfile = file("sumigetw-c.log", "wt")
        self.clogfile.write("Started client log at %s\n" % time.asctime())

        self.app = app
        self.textCtrl = wx.TextCtrl(self, -1, size=(-1, -1), 
                         style=wx.TE_MULTILINE | wx.TE_READONLY)
        box = wx.BoxSizer(wx.VERTICAL)
        box.Add(self.textCtrl, 1, wx.EXPAND)
        self.SetAutoLayout(True)
        self.SetSizer(box)
        self.Layout()

        # wx.TextCtrl's fill up at a default of 30,000 characters (can be
        # extended, but there still may be OS-defined limits). Could use a
        # wx.TE_RICH on Win32 for >64K but what about other systems? There
        # is still a limit. 
        wx.EVT_TEXT_MAXLEN(self, self.textCtrl.GetId(), self.OnLogFull)

        def log(msg):
            print msg
            self.Write("%s\n" % msg)
        sumiget.log = log

    def Write(self, msg):
        self.clogfile.write(msg)
        try:
            self.textCtrl.AppendText(msg)
        except Exception, x:
            print "Failed to write: %s, trying again." % msg
            self.OnLogFull(None)
            self.textCtrl.AppendText(msg)

    def OnLogFull(self, event):
        self.textCtrl.Clear()

class ExitPanel(wx.Panel):
    """Panel to exit."""
    def __init__(self, parent, app):
        wx.Panel.__init__(self, parent, -1)

        self.app = app

        # Close whenever the exit panel is displayed (tab clicked), not
        # whenever focus is set to it (EVT_SET_FOCUS), as that would
        # require clicking the panel itself.
        wx.EVT_PAINT(self, self.Terminate)

    def Terminate(self, event):
        log("Gracefully closing")
       
        try:
            self.app.OnCloseFrame()   # save win size
            self.app.OnExit()
        except Exception, x:
            if not isinstance(x, SystemExit):
                log("!! Exception when closing: %s: %s" % (str(sys.exc_info()), x))
        raise SystemExit

class SLogPanel(wx.Panel):
    """Server log panel."""
    def __init__(self, parent, app):
        wx.Panel.__init__(self, parent, -1)

        self.slogfile = file("sumigetw-s.log", "wt")
        self.slogfile.write("Started server log at %s\n" % time.asctime())

        self.app = app
        self.servlog = wx.TextCtrl(self, -1, 
                style=wx.TE_MULTILINE | wx.TE_READONLY)
        box = wx.BoxSizer(wx.VERTICAL)
        box.Add(self.servlog, 1, wx.EXPAND)
        self.SetAutoLayout(True)
        self.SetSizer(box)
        self.Layout()
        
        wx.EVT_TEXT_MAXLEN(self, self.servlog.GetId(), self.OnLogFull)

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
            self.Write("%s\n" % msg)
        sumiserv.log = log

        thread.start_new_thread(wrap_thread, (sumiserv.main, ((),)))
        self.started = True

    def Write(self, msg):
        self.slogfile.write(msg)
        try:
            self.servlog.AppendText(msg)
        except Exception, x:
            print "Failed to write: %s, trying again." % msg
            self.OnLogFull(None)
            self.servlog.AppendText(msg)

    def OnLogFull(self, event):
        self.servlog.Clear()

CTL_BANDWIDTH = 500
CTL_CRYPTO = 501
CTL_DCHAN  = 502
CTL_DLDIR  = 503
CTL_BROWSE = 504
CTL_MYIP   = 505
CTL_MYPORT = 506
CTL_MTU    = 507
CTL_TYPE   = 508
CTL_CODE   = 509

class CConfigPanel(wx.Panel):
    """Client configuration panel."""
    def __init__(self, parent, app):
        wx.Panel.__init__(self, parent, -1, style=wx.WANTS_CHARS)

        self.app = app     

        # Layout here is all done manually without sizers
        # XXX: TODO: two important things here:
        # - use sizers, eschew absolute positioning
        # - load config widget values on focus (what event?), so they
        #   will reload after every validate_config()--it may change it

        # Bandwidth in bits per second
        # Load predefined values, sorted descending
        bandwidths = [1000000000, 100000000, 10000000, 1500000, 768000, 384000, 56000, 28000]
        bandwidths.append(self.app.client.config["bandwidth"])
        # Remove duplicates (can use sets in Python 2.4)
        bandwidths = dict.fromkeys(bandwidths).keys()
        bandwidths.sort()
        bandwidths = map(str, bandwidths)
        bandwidths.reverse()

        self.bw_label = wx.StaticText(self, -1, "Bandwidth (bps):", 
                                     wx.Point(0, 0), wx.Size(-1, -1))
        self.bw = wx.ComboBox(self, CTL_BANDWIDTH, 
                             str(self.app.client.config["bandwidth"]), 
                             wx.Point(90, 0),
                             wx.Size(95, -1),
                             choices=bandwidths, style=wx.CB_DROPDOWN)

        wx.EVT_TEXT(self, CTL_BANDWIDTH, self.OnBandwidthChange)

        # TODO: Checkbox for crypt

        # Data channel type
        # ICMP here has 2^16 combinations, for each type+code.
        # This is what to do: split "port" into "type" and "code"
        # When ICMP selected, show type&code. When other, show port.
        # Encode as type*0x100+code, thats how sumiserv interprets it.
        self.dchan_label = wx.StaticText(self, -1, "Data channel:", 
                                        wx.Point(0, 70), wx.Size(-1, -1))
        dchans_rep = ["UDP", "ICMP Direct", "ICMP Echo"]
        #self.dchans_code = ['u', 'e'] + (['?'] * 256)
        self.dchans_code = ['u', 'i', 'e']
        dchan2n = {'u': 0, 'i': 1, 'e': 2}
        #for x in range(0, 256):
        #    dchans_rep.append("ICMP Type=%d Code=0" % x)
        #    dchan2n["i%d,%d" % (x, 0)] = 2 + x
        #    self.dchans_code[x + 2] = "i%d,%d" % (x, 0)
        self.dchan = wx.Choice(self, CTL_DCHAN, wx.Point(90, 70), 
                wx.Size(-1, -1), choices=dchans_rep)
        self.dchan.SetSelection(dchan2n[self.app.client.config
                ["data_chan_type"]])
        wx.EVT_CHOICE(self, CTL_DCHAN, self.OnDChanChange)

        # Download directory, [...] common open file dialog
        self.dldir_label = wx.StaticText(self, -1, "Download to:", 
                                        wx.Point(0, 110), wx.Size(-1, -1))
        self.dldir = wx.TextCtrl(self, CTL_DLDIR, 
                self.app.client.config["dl_dir"],
                wx.Point(90, 110), wx.Size(260, -1), 
        # Have to change dldir using browse button, can't edit it directly.
        # Possible but I don't allow this, so validation can be done in the
        # common dialog instead of in user program. 
                                style=wx.TE_READONLY)
        self.dldir_browse = wx.Button(self, CTL_BROWSE, "...", 
                                     wx.Point(90 + 260, 110), wx.Size(20, -1))
        wx.EVT_BUTTON(self, CTL_BROWSE, self.OnDldirBrowse)

        # Send to IP Address ("" = get default IP)
        self.myip_label = wx.StaticText(self, -1, "IP Address:", 
                                       wx.Point(250, 0), wx.Size(-1, -1))
        myip = self.app.client.config["myip"]
        if len(myip) == 0: myip = "(default)"
        self.myip = wx.TextCtrl(self, CTL_MYIP, 
                               myip, 
                               wx.Point(250 + 90, 0), wx.Size(-1, -1))
        wx.EVT_TEXT(self, CTL_MYIP, self.OnIPChange)

        # 16-bit (UDP) port, if applicable 
        self.myport_label = wx.StaticText(self, -1, "UDP Port:", 
                                         wx.Point(250, 80), wx.Size(-1, -1))
        # IntCtrl is appealing, but not on Windows? Look into this.
        self.myport = IntCtrl(self, CTL_MYPORT, 
                                 self.app.client.config["myport"],
                                 wx.Point(250 + 90, 80), wx.Size(-1, -1))
        self.myport.SetMin(0)   # 0 port..heh
        self.myport.SetMax(65535)
        EVT_INT(self, CTL_MYPORT, self.OnPortChange)

        self.myport_label.Show(False)
        self.myport.Show(False)

        self.type_label = wx.StaticText(self, -1, "Type:", 
                                       wx.Point(250, 80), wx.Size(-1, -1))
        self.type = IntCtrl(self, CTL_TYPE, 
                              self.app.client.config["myport"] / 0x100,
                              wx.Point(250 + 40, 80), wx.Size(40, -1))

        self.code_label = wx.StaticText(self, -1, "Code:", 
                               wx.Point(250 + 40 + 40, 80), wx.Size(-1, -1))

        self.code = IntCtrl(self, CTL_CODE, 
                              self.app.client.config["myport"] % 0x100,
                              wx.Point(250 + 40 + 40 + 40, 80), wx.Size(40, -1))
        EVT_INT(self, CTL_TYPE, self.OnTypeCodeChange)
        EVT_INT(self, CTL_CODE, self.OnTypeCodeChange)
        self.OnDChanChange()     # Hide/show correct controls

        # MTU. Combo box with common dropdowns, like bandwidth?
        # Only problem is, how do you make combo box only accept ints?
        # Just using an IntCtrl for now
        self.mtu_label = wx.StaticText(self, -1, "MTU:", 
                                      wx.Point(250, 40), wx.Size(-1, -1))
        self.mtu = IntCtrl(self, CTL_MTU, 
                             self.app.client.config["mtu"],
                             wx.Point(250 + 90, 40), wx.Size(-1, -1))
        EVT_INT(self, CTL_MTU, self.OnMTUChange)

        # TODO: Rwinsz, in seconds. Slider - 1 to 15 or so?
        # TODO: Maxwait, time to wait before handshake. Slider again?
        # Actually, don't need to clutter dialog up with these


    def OnBandwidthChange(self, event):
        bw = event.GetString()
        if len(bw) == 0: return

        self.app.client.config["bandwidth"] = int(bw)

    #def OnCryptoChange(self, event):
        #self.app.client.config["crypto"] = self.cryptos[event.GetInt()]

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
        # wx.DirDialog or wx.FileDialog
        # EAC uses wx.FileDialog and ignores the filename. I like that idea,
        # because wx.DirDialog isn't as good in my opinion.
        
        if not os.access(self.app.client.config["dl_dir"], os.W_OK | os.X_OK):
            # Can't read or cd to directory so default to current directory
            self.app.client.config["dl_dir"] = os.getcwd()
        dlg = wx.FileDialog(self, "Choose location", 
                  self.app.client.config["dl_dir"], "Filename is ignored",
                  "All files (*.*)|*.*", wx.SAVE)
        if dlg.ShowModal() == wx.ID_OK:
            self.app.client.config["dl_dir"] = os.path.dirname(dlg.GetPath())
            self.dldir.SetValue(self.app.client.config["dl_dir"] + 
                                os.path.sep)

    def OnIPChange(self, event):
        myip = event.GetString()
        if myip == "(default)": myip = ""
        self.app.client.config["myip"] = myip

    def OnPortChange(self, event):
        self.app.client.config["myport"] = event.GetEventObject().GetValue()

    def OnTypeCodeChange(self, event):
        self.app.client.config["myport"] = self.type.GetValue() * 0x100 + self.code.GetValue()

    def OnMTUChange(self, event):
        self.app.client.config["mtu"] = event.GetEventObject().GetValue()
 
# This is for mode-less file dialog, but wx.EVT_CLOSE isn't triggered
#        self.browse_dlg.Show()
#        wx.EVT_CLOSE(self.browse_dlg, self.OnDldirBrowseClose)
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

class SConfigPanel(wx.Panel):
    """Server configuration panel."""
    def __init__(self, parent, app):
        wx.Panel.__init__(self, parent, -1, style=wx.WANTS_CHARS)

        self.app = app   
        self.share = wx.CheckBox(self, CTL_SHARE, "Enable sharing")
        box = wx.BoxSizer(wx.VERTICAL)
        box.Add(self.share, 1, wx.EXPAND)
        self.SetAutoLayout(True)
        self.SetSizer(box)
        self.Layout()

        self.share.SetValue(self.app.client.config["share"])

        wx.EVT_CHECKBOX(self, CTL_SHARE, self.OnToggleSharing)

    def OnToggleSharing(self, event):
        self.app.client.config["share"] = self.share.GetValue()

        if self.app.client.config["share"] and not self.app.nb.slog.started:
            self.app.nb.slog.start()
        elif not self.app.client.config["share"]:
            # Too annoying?
            #dlg = wx.MessageDialog(self.app.frame, 
            #      "The server will be shutdown once sumigetw is restarted.",
            #      "SUMI Server", wx.OK | wx.ICON_INFORMATION);
            #dlg.ShowModal()
            pass

# Somewhat based on wx.ListCtrl demo
class TransferListCtrl(wx.ListCtrl, ListCtrlAutoWidthMixin):
    """List control handling the list of file transfers."""
    def __init__(self, parent, ID, pos=wx.DefaultPosition,
                 size=wx.DefaultSize, style=0):
        wx.ListCtrl.__init__(self, parent, ID, pos, size, style)
        ListCtrlAutoWidthMixin.__init__(self)

class TransferPanel(wx.Panel, ColumnSorterMixin):
    """Panel encapsulating the list transfer control."""
    def __init__(self, parent, app):
        wx.Panel.__init__(self, parent, -1, style=wx.WANTS_CHARS)
                                                 #wx.TAB_TRAVERSAL)
        # TODO: Column sorting is disabled now because nick2index loses
        # its associations and starts writing to the wrong column.
        #ColumnSorterMixin.__init__(self, 3)

        tID = wx.NewId()

        self.il = wx.ImageList(16, 16)

        self.app = app

        self.idx1 = self.il.Add(getSmilesBitmap())
        self.sm_up = self.il.Add(getSmallUpArrowBitmap())
        self.sm_dn = self.il.Add(getSmallDnArrowBitmap())

        self.list = TransferListCtrl(self, tID,
                                 style=wx.LC_REPORT #| wx.SUNKEN_BORDER
                                 | wx.LC_EDIT_LABELS
                                 #| wx.LC_VRULES | wx.LC_HRULES
                                 | wx.LC_HRULES, 
                                 size=(100,100), pos=(50,50))
        self.list.SetImageList(self.il, wx.IMAGE_LIST_SMALL)

        self.itemDataMap = {}

        self.SetupList()


        # XXX: These are left over from wx.ListCtrl demo. 
        # TODO: Do something useful with them
        wx.EVT_SIZE(self, self.OnSize)
        wx.EVT_LIST_ITEM_SELECTED(self, tID, self.OnItemSelected)
        wx.EVT_LIST_ITEM_DESELECTED(self, tID, self.OnItemDeselected)
        wx.EVT_LIST_ITEM_ACTIVATED(self, tID, self.OnItemActivated)
        wx.EVT_LIST_DELETE_ITEM(self, tID, self.OnItemDelete)
        wx.EVT_LIST_COL_CLICK(self, tID, self.OnColClick)
        wx.EVT_LIST_COL_RIGHT_CLICK(self, tID, self.OnColRightClick)
        wx.EVT_LIST_COL_BEGIN_DRAG(self, tID, self.OnColBeginDrag)
        wx.EVT_LIST_COL_DRAGGING(self, tID, self.OnColDragging)
        wx.EVT_LIST_COL_END_DRAG(self, tID, self.OnColEndDrag)
        # Begin and end rename
        wx.EVT_LIST_BEGIN_LABEL_EDIT(self, tID, self.OnBeginEdit)
        wx.EVT_LIST_END_LABEL_EDIT(self, tID, self.OnEndEdit)

        wx.EVT_LEFT_DCLICK(self.list, self.OnDoubleClick)
        wx.EVT_RIGHT_DOWN(self.list, self.OnRightDown)

        # for wxMSW
        wx.EVT_COMMAND_RIGHT_CLICK(self.list, tID, self.OnRightClick)

        # for wxGTK
        wx.EVT_RIGHT_UP(self.list, self.OnRightClick)

    def SetupList(self):
        """Sets up the columns of the transfer list control."""
        info = wx.ListItem()
        info.m_mask = (wx.LIST_MASK_TEXT | wx.LIST_MASK_IMAGE |
                wx.LIST_MASK_FORMAT)
        info.m_image = -1
        info.m_format = 0

        colnames = ['Filename', 'Peer', 'ID', 'T/D', 'Status', 
                    'Progress', 'Size', 
                    'Bytes', 'Rate', 'From', 
                    'Missing', 'Rexmits', 'ETA']
        colfmt = [0, 0, 0, 0, 0, wx.LIST_FORMAT_RIGHT, wx.LIST_FORMAT_RIGHT, 
                  wx.LIST_FORMAT_RIGHT, wx.LIST_FORMAT_RIGHT, 
                  wx.LIST_FORMAT_RIGHT, wx.LIST_FORMAT_RIGHT,
                  wx.LIST_FORMAT_RIGHT, 0, wx.LIST_FORMAT_RIGHT ]

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
        #    self.list.SetColumnWidth(x, wx.LIST_AUTOSIZE)

        # This is neat, column widths are saved and restored so they are always
        # exactly as you (user) left them. No autosize to worry about.
        colno = 0
        for x in self.app.client.config["colwidths"]:
            self.list.SetColumnWidth(colno, x)
            colno += 1
        #self.list.SetColumnWidth(0, 100)

        self.currentItem = 0

    # Used by the wx.ColumnSorterMixin, see wxPython/lib/mixins/listctrl.py
    def GetListCtrl(self):
        return self.list

    # Used by the wx.ColumnSorterMixin, see wxPython/lib/mixins/listctrl.py
    def GetSortImages(self):
        # These are the icons that appear for ascending/descending sorting
        return (self.sm_dn, self.sm_up)

    # Right click
    def OnRightDown(self, event):
        self.x = event.GetX()
        self.y = event.GetY()
        print "x, y = %s\n" % str((self.x, self.y))
        item, flags = self.list.HitTest((self.x, self.y))
        if flags & wx.LIST_HITTEST_ONITEM:
            self.list.Select(item)
        event.Skip()


    def getColumnText(self, index, col):
        item = self.list.GetItem(index, col)
        return item.GetText()

    # An item was selected
    def OnItemSelected(self, event):
        ##print event.GetItem().GetTextColour()
        self.currentItem = event.m_itemIndex
        print "OnItemSelected: %s, %s, %s, %s\n" % (
                            self.currentItem,
                            self.list.GetItemText(self.currentItem),
                            self.getColumnText(self.currentItem, 1),
                            self.getColumnText(self.currentItem, 2))
        # Able to prevent item from being selected, if needed
        #if self.currentItem == 10:
        #    print "OnItemSelected: Veto'd selection\n"
        #    #event.Veto()  # doesn't work
        #    # this does
        #    self.list.SetItemState(10, 0, wx.LIST_STATE_SELECTED)
        event.Skip()


    # An item was deselected
    def OnItemDeselected(self, evt):
        item = evt.GetItem()
        print "OnItemDeselected: %d" % evt.m_itemIndex

        # Show how to reselect something we don't want deselected
        #if evt.m_itemIndex == 11:
        #    wx.CallAfter(self.list.SetItemState, 11, wx.LIST_STATE_SELECTED,
        #    wx.LIST_STATE_SELECTED)


    def OnItemActivated(self, event):
        self.currentItem = event.m_itemIndex
        print "OnItemActivated: %s\nTopItem: %s" % (
                           self.list.GetItemText(self.currentItem), 
                           self.list.GetTopItem())

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
        print "OnColRightClick: %d %s\n" % (
                           event.GetColumn(), 
                           (item.GetText(), 
                               item.GetAlign(),
                               item.GetWidth(), 
                               item.GetImage()))

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
        # save config to config.txt, like with sumiserv
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
    
    def OnResume(self, event): 
        index = self.list.GetFirstSelected()
        while index != -1:
            print "      %s: %s\n" % (self.list.GetItemText(index),
                    self.getColumnText(index, COL_PEER))

            snick = self.getColumnText(index, COL_PEER)

            u = self.app.client.senders[snick]
            transport, filename = u["transport"], u["filename"]
            thread.start_new_thread(wrap_thread,
                    (self.app.client.request, [[transport, snick, filename]]))

            index = self.list.GetNextSelected(index)
    
    def OnRename(self, event):
        self.list.EditLabel(self.currentItem)
        print "TODO: Rename file"


    # Right-click item context menu, transfer-specific functions
    def OnRightClick(self, event):
        print "OnRightClick %s\n" % self.list.GetItemText(self.currentItem)

        # only do this part the first time so the events are only bound once
        if not hasattr(self, "popupID1"):
            self.popup_open = wx.NewId()
            self.popup_opendir = wx.NewId()
            self.popup_abort = wx.NewId()
            self.popup_resume = wx.NewId()
            self.popup_rename = wx.NewId()
            #self.popupID1 = wx.NewId()
            #self.popupID2 = wx.NewId()
            #self.popupID3 = wx.NewId()
            #self.popupID4 = wx.NewId()
            #self.popupID5 = wx.NewId()
            #self.popupID6 = wx.NewId()
            wx.EVT_MENU(self, self.popup_open, self.OnOpen)
            wx.EVT_MENU(self, self.popup_opendir, self.OnOpenDir)
            wx.EVT_MENU(self, self.popup_abort, self.OnAbort)
            wx.EVT_MENU(self, self.popup_resume, self.OnResume)
            wx.EVT_MENU(self, self.popup_rename, self.OnRename)
            #wx.EVT_MENU(self, self.popupID1, self.OnPopupOne)
            #wx.EVT_MENU(self, self.popupID2, self.OnPopupAbort)
            #wx.EVT_MENU(self, self.popupID3, self.OnPopupThree)
            #wx.EVT_MENU(self, self.popupID4, self.OnPopupFour)
            #wx.EVT_MENU(self, self.popupID5, self.OnPopupFive)
            #wx.EVT_MENU(self, self.popupID6, self.OnPopupSix)

        # make a menu
        menu = wx.Menu()
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
        self.PopupMenu(menu, wx.Point(self.x, self.y))
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
            print "      %s: %s\n" % (self.list.GetItemText(index),
                    self.getColumnText(index, COL_PEER))

            snick = self.getColumnText(index, COL_PEER)
            self.app.client.abort(self.app.client.senders[snick])
            index = self.list.GetNextSelected(index)
    
    # Examples
    def OnPopupOne(self, event):
        print "Popup one\n"
        print "FindItem:", self.list.FindItem(-1, "Roxette")
        print "FindItemData:", self.list.FindItemData(-1, 11)

    def OnPopupThree(self, event):
        print "Popup three\n"
        self.list.ClearAll()
        wx.CallAfter(self.SetupList)

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

class DropTarget(wx.FileDropTarget):
    """Target to notify SUMIApp when files are dropped."""
    def __init__(self, app, drop):
        wx.FileDropTarget.__init__(self)
        self.app = app
        self.drop = drop

    def OnData(self, *args):
        self.GetData()
        self.app.OnDropFiles(self.drop.GetFilenames())

class SUMIApp(wx.App):
    """The SUMI GUI application."""
    def __init__(self):
        wx.App.__init__(self, 0)

    def OnInit(self):
        print "OnInit"
        # Setup receive requests thread/send requests. Do this first because
        # it might be the last thing we do.
        self.RecvReq()

        self.client = sumiget.Client()

        wx.InitAllImageHandlers()

        # Frame to hold the notebook
        self.frame = wx.Frame(None, -1, "SUMI", pos=(50,50), 
                        style=wx.NO_FULL_REPAINT_ON_RESIZE |
                        wx.DEFAULT_FRAME_STYLE | wx.TAB_TRAVERSAL)

        # Drag and drop -- eventually calls OnDropFiles here
        drop = wx.FileDataObject()
        self.drop_target = DropTarget(self, drop)
        self.drop_target.SetDataObject(drop)
        self.frame.SetDropTarget(self.drop_target)
        if hasattr(self.frame, "DragAcceptFiles"):
            log("Enabling drag-and-drop")
            self.frame.DragAcceptFiles(True)
        else:
            log("Disabling drag-and-drop, not supported")

        self.frame.icon = wx.Icon("sumi.ico", wx.BITMAP_TYPE_ICO)
        if self.frame.icon:
            self.frame.SetIcon(self.frame.icon)
        else:
            print "failed to set icon"

        #self.frame.CreateStatusBar()
        self.nb = MainNotebook(self.frame, self)

        # No menubar
        #menuBar = wx.MenuBar()
        #menu = wx.Menu()
        #menu.Append(101, "E&xit\tAlt-X", "Exit demo")
        #wx.EVT_MENU(self, 101, self.OnExit)
        #menuBar.Append(menu, "&File")
        #self.frame.SetMenuBar(menuBar)

        wx.EVT_CLOSE(self.frame, self.OnCloseFrame)

        self.SetupStartfile()

        # Setup the SUMI 
        # Only really need one of these each per transfer
        thread.start_new_thread(wrap_thread, (self.client.thread_timer, ()))
        thread.start_new_thread(wrap_thread, (self.client.recv_packets, ()))
   
        print "Sys args=", sys.argv 
        if len(sys.argv) != 1:
            thread.start_new_thread(wrap_thread, 
                    (self.ReqThread, [sys.argv[1:]]))
        else:
            log("No request specified! Starting up without.")

        self.frame.Show(True)
        # Restore saved window size
        self.frame.SetSize(self.client.config["winsize"])

        # If no arguments, show config, else show transfer panel
        if len(sys.argv) == 1:
            log("No arguments--showing config")
            self.nb.cfgc.SetFocus()
            self.nb.SetSelection(1)
        else:
            self.nb.xfpanel.SetFocus()

        self.SetTopWindow(self.frame)
        return True

    def SetupStartfile(self):
        """Initialize os.startfile if it is not available on this platform."""

        # Currently, os.startfile is only available on Win32. Provide a
        # reasonable alternative if not available.
        if not hasattr(os, "startfile"):
            def startfile(file):
                os.system(self.client.cfg.get("startfile", "firefox %s") % file)
            os.startfile = startfile

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
            ss.send("\t".join(sys.argv[1:]))
            ss.close()
            sys.exit(0)
            # If this code is ran (above) but another instance is not
            # running, then REQPORT is in use by someone else. Change REQPORT.
        ss.listen(5)
        thread.start_new_thread(wrap_thread, (self.RecvReqThread, (ss,)))


    def RecvReqThread(self, ss):
        """Thread that receives socket connections in order to handle 
            additional requests after the program is started."""
        while True:
            r = ss.accept()
            # Sometimes raises 'ValueError: unpack list of wrong size'
            if type(r) != types.ListType and len(r) != 2:
                log("Accept returned: "+str(r))
                break

            cs, addr = r
            data = cs.recv(256)
            args = data.split("\t")
            print "Received req from",addr,"=",data
            thread.start_new_thread(wrap_thread, (self.ReqThread, (args,)))

    def ReqThread(self, args):
        """Thread that handles a request."""
        
        self.client.set_callback(self.Callback)
        self.client.request(args)

        # End of thread

    def SizeCols(self):
        """Autosize the columns."""
        # No, don't call this. Instead use widths from config file
        for x in range(0, COL_LAST):
            self.nb.xfpanel.list.SetColumnWidth(x, wx.LIST_AUTOSIZE)


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
        if (cmd == "new_xfer"):
            global nick2index, last_index
            transport, nick, filename = args

            # nick2index associates the nickname with the location in the list
            # TODO: Use transfer key instead, as its unique. Then might be able
            # to do multiple transfers per nick
            if nick2index.has_key(nick):
                index = nick2index[nick]
                if self.nb.xfpanel.getColumnText(index, COL_STATUS) == \
                    'Transferring...':
                    print "ERROR: In-progress transfer from",\
                            nick,"at",index,"already"
                    print "Currently you can only have one"\
                            "transfer per user, sorry"
                    return 
            else:
                nick2index[nick] = last_index
                index = nick2index[nick]
                last_index += 1

            print "Inserting at index",index
            self.nb.xfpanel.list.InsertImageStringItem(index, nick, 
                    self.nb.xfpanel.sm_dn)
            self.nb.xfpanel.itemDataMap[index] = [0] * (COL_LAST + 1)
            self.SetInfo(nick, COL_FILENAME, filename)
            self.SetInfo(nick, COL_PEER, nick)
            self.SetInfo(nick, COL_STATUS, "Requesting")
            #self.SizeCols()
        elif (cmd == "t_wait"):   # waiting for transport
            self.SetInfo(nick, COL_STATUS, "Transport loading")
        elif (cmd == "1xferonly"):  # transfer already in progress
            self.SetInfo(nick, COL_STATUS, "Another transfer in progress")
            self.SetColor(nick, wx.RED)  # Maybe queue it instead?
        elif (cmd == "auth_crc_fail"):
            # TODO: this should cause the pkt to be re-requested; it could
            # just be a transient network error
            self.SetInfo(nick, COL_STATUS, 
                "Auth packet corrupted, please try again.")
            self.SetColor(nick, wx.RED)
        elif (cmd == "bad_file"): 
            self.SetInfo(nick, COL_STATUS, "Couldn't resume from %s" %
                    args[0])
            self.SetColor(nick, wx.RED)

        elif (cmd == "hash_start"):
            self.SetInfo(nick, COL_STATUS, "Verifying...")
        elif (cmd == "hashing"):
            self.SetInfo(nick, COL_BYTES, str(args[0]))
        elif (cmd == "hash_ok"):
            self.SetInfo(nick, COL_STATUS, "Verified OK")
            self.SetColor(nick, wx.Colour(32, 128, 32))
        elif (cmd == "hash_fail"):
            self.SetInfo(nick, COL_STATUS, "Hash failed")
            self.SetInfo(nick, wx.RED)

        elif (cmd == "t_import_fail"): # transport failed to load
            self.SetInfo(nick, COL_STATUS, "Bad transport: %s" % args[0])
            self.SetColor(nick, wx.RED)
        elif (cmd == "t_no_recvmsg"):
            self.SetInfo(nick, COL_STATUS, 
                "Can't use %s w/ crypt_req (no recvmsg)" % args[0])
            self.SetColor(nick, wx.RED)
        elif (cmd == "t_user"):
            self.SetInfo(nick, COL_STATUS, "Connecting...")
        elif (cmd == "t_user_fail"): 
            self.SetInfo(nick, COL_STATUS, "User failure: %s" % args[0])
            self.SetColor(nick, wx.RED)
        elif (cmd == "error"):
            self.SetInfo(nick, COL_STATUS, "Error: %s" % args[0])
            self.SetColor(nick, wx.RED)
        elif (cmd == "req_sent"):  # request was sent
            self.SetInfo(nick, COL_STATUS, "Handshaking")
        elif (cmd == "req_count"): # request handshake countdown+status
            self.SetInfo(nick, COL_STATUS, "%s (%d)" % (args[1], args[0]))
        elif (cmd == "rexmits"):   # retransmission
            self.SetInfo(nick, COL_REXMITS, str(args[0]))
        elif (cmd == "lost"):      # outstanding lost packets
            self.SetInfo(nick, COL_MISSING, str(len(args[0])))
        elif (cmd == "timeout"):   # timed out/no such nick
            self.SetInfo(nick, COL_STATUS, "Timeout")
            self.SetColor(nick, wx.RED)
        elif (cmd == "info"):   # sent on reception of auth packet, ready
            (size, prefix, filename, transport, dchantype) = args
            print "Info: ", args

            self.SetInfo(nick, COL_STATUS, "Authenticating")
            self.SetInfo(nick, COL_FILENAME, filename)
            self.SetInfo(nick, COL_SIZE, str(size))
            self.SetInfo(nick, COL_BYTES, "0")
            self.SetInfo(nick, COL_PEER, str(nick))
            self.SetInfo(nick, COL_PREFIX, prefix)
            self.SetInfo(nick, COL_VIA, "%s/%s" % (transport, dchantype))

            # can't set range to file size because multiples of 1048576
            # do not show up, at any SetValue(), in Win32 only
            #self.gauge.SetRange(10000)  #args[0])
            self.filename = filename
        elif (cmd == "rate"):   # update rate of transfer
            (rate, eta) = args
            self.SetInfo(nick, COL_RATE, "%.1fKB/s" % (rate / 1024))
            self.SetInfo(nick, COL_ETA, "%d min" % int(eta / 60))
        elif (cmd == "recv_1st"):
            # One-time actions that take effect throughout the whole
            # transfer but have no need to be re-set every packet. Note this
            # message does not include any args; write will be called w/ args.
            # Like xchat's dcc, blue=transferring, green=done, & red=err
            self.SetColor(nick, wx.BLUE)
            self.SetInfo(nick, COL_STATUS, "Transferring...")
        elif (cmd == "write"):
            #self.gauge.SetValue(int(args[1]))
            # XXX Is this correct? Lost packets? Will overestimate.
            #    % done = (total size of pcks recvd) / (file size) * 100
            # Always round down (to ceiling) when calculating file progress
            # so the percentage reaches 100% only when completely done!
            #self.gauge.SetValue(int(args[1] * 10000. / args[3]))
            # ARGS = pktstart, pktend, pktlength, totlen
            #         ^ file offsets ^   MSS     size
            #self.info.SetLabel("Transferring... %.3f%% from %s" % 
            #    (args[1] * 100. / args[3], args[4][0]))
            #self.SetInfo(nick, COL_PROGRESS, "%.3f%%" % 
            #             (args[1] * 100. / args[3]))

            # New write args: offset, n_received_bytes, total_size
            (offset, bytes, size, addr) = args
            self.SetInfo(nick, COL_BYTES, str(bytes))
            percent = "%.1f%%" % (bytes * 100. / size)
            # When done, drop trailing floating point to accommodate the
            # length of '100' compared to anything less. Minor cosmetic.
            if (percent == "100.0%"): percent = "100%"

            #self.SetInfo(nick, COL_PROGRESS, "%.1f%%" % 
            #    (bytes * 100. / size))
            self.SetInfo(nick, COL_PROGRESS, percent)
            # IP:Port
            #self.SetInfo(nick, COL_FROM, ":".join(map(str, addr)))
            # just IP - I like this one better
            self.SetInfo(nick, COL_FROM, addr[0])
        elif (cmd == "xfer_fin"):       # Transfer finished
            (duration, size, speed, all_lost) = args
            self.SetInfo(nick, COL_STATUS, "Complete")
            self.SetInfo(nick, COL_RATE, "%d" % speed)
            self.SetColor(nick, wx.Colour(32, 128, 32))   # a suitable green
            #self.info.SetLabel("Complete %d B @ %d kB/s: %s" % 
            #    (size, speed, all_lost))
        elif (cmd == "aborted"):
            self.SetInfo(nick, COL_STATUS, "Aborted")
            self.SetColor(nick, wx.RED)
            # TODO: Stop request thread? It still sends acks...
        else:
            print "??? Unrecognized command: %s %s" % (cmd, args)
            #assert False, "Unrecognized command: %s %s" % (cmd, args)

    def OnExit(self, evt=0):
        # If closed by "X" button on Win32, self.frame will already be
        # destroyed, so don't destroy it. But if closed programatically,
        # (by calling us--OnExit), then self.frame needs to be destroyed.
        if self.frame: 
            self.frame.Close(True)

        # Use console-only log when shutting down, as log panel is unavailable
        def console_log(msg):
            print msg

        sumiget.log = console_log

        self.client.on_exit()   # Save client config

    def OnCloseFrame(self, evt=0):
        # Save size of *frame* (not xfpanel) before the frame closes
        # (Has to be done here, not in OnExit because already closed by then)
        self.client.config["winsize"] = self.frame.GetSizeTuple()
        if (evt != 0): evt.Skip()

    def OnDropFiles(self, filenames):
        #filenames = self.dropped_files.GetFilenames()
        log("DROP: %s" % str(filenames))
        for f in filenames:
            thread.start_new_thread(wrap_thread, 
                    (self.ReqThread, [[f]]))

def wrap_thread(f, args):
    try:
        print "Calling %s(%s)" % (f, args)
        f(*args)
    except None: #Exception, x:
        print "(thread) Exception: %s at %s" % (x,
                sys.exc_info()[2].tb_lineno)
        raise x

def main():
    print "Loading app..."
    app = SUMIApp()
    print "Running main loop"
    app.MainLoop()

# DATA FUNCTIONS BEGIN HERE

# Bitmaps - from images.py from wxPython demo, modified for new version
def getSmilesData():
    return \
'\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x10\x00\x00\x00\x10\x08\x06\
\x00\x00\x00\x1f\xf3\xffa\x00\x00\x00\x04sBIT\x08\x08\x08\x08|\x08d\x88\x00\
\x00\x02\x97IDATx\x9ce\x93\xcdkSi\x18\xc5\x7f\xef\xfd\x88iC\x85\x11\xeaW\xbd\
1Z\x83D\x04\x11a\x18\xc4\x8e\xd8\x8e\x9dB\x87Y\xe8N\xc2(6\xf1\x82[).\xdd\xa6\
\xfe\x01nj7\xf3?\x14\x06k\xbb)sA\x04Q\xd3!\tZ\xda\xe9\x07\xc8\xc0\x08\xc5\
\xb64\xefm<.r[[}\xe0,\xde\x8f\xf3>\xbc\xe7<\x07\xe3\xb8\xec\xc5\xf4\xf4\xb4\
\x8a\xc5[\xca\xe5\x8e\xc9\xf3\x8c|\xdfQ>\x1f(\x0c\xcb\x8a\xa2H\xdf\xde\xdf\
\xb7\x08\xc3\xb2\x82 \xa3J\xe5\'U\xab7emQ\xd6\xdeR\xb5\xfa\x9b*\x95\xac\x82\
\xc0(\x0cK\xfb\x1f1\x8e\x0b\xc0\xf5_~V6\xfb?O\x9e\xfc\x8e\xef[`\x03X\x07Z@\
\x13\x98\'\x8ek\xdc\xbfoYZ\xba\xcc\xd4\xf3\xc8\x008\x00\xf7\xcaw\x95\xcd\xc2\
\xf8x\x05\xdf/\x00\x99\x84(\xda\xb5\x05l\xe2\xfb\x86\xf1\xf1\x03d\xb3\xb3\
\xdc+\xdfi\x1fFQ\xa4 8$kk\x92\x16%=\xd3\xe8\xe8\xa8\x00IEIE\x01\xea\xee\xee\
\x96\xd4)\xa9C\xd6\xa2\xe0\x04mM\xc2\xb0\xacS\xa7\xb6y\xf8\xf0\x11\xe0\x02\
\xff`\xcc\x10\x00R\x11X\xa3PxG\xbd^G\xea\x04\xb5`\xdb0\xf6\xb8\xc5\xc2R\x11g\
f\xe6/\x86\x87{\x80U`\x1ex\xcd\xd7j\x02\xab,//\xef\xd9\xfb\x0c\xcdN\x86\x07\
\xba\x98\x99\x99\xc4\xf8\xbe\xa3\x8d\x8d\x07\xf8~\x17\xb0\xc5\xc8\xc8\x07&&\
\xec\xaep\xb0\x9c\x08\x9a\x90[-X;L\xbc\xe5\x929\xb9\xd4\x16\x11l\xa2\xf8\'&&\
b`\r\xa8\x02\x8d=d\x81\xb69}"\rq\x07\xc4i\x00\x9c\\\xae\x87Fc\x05\xf8\x0fhP(\
\xbc\x04^$\x9d\xf5\x95L\x0c-\x87\x85\x0f\x9f`\xb3\x8bF\xdd\x90;\xd9\x8d\xd7\
\xdf\xff+\x93\x93\x7fr\xfe|\n\x10\xb5\x1ad2bc\xa71\x9f\x81mh\x19.\x9d\xebB\
\x8b=\xb0y\x90\xc9g\x1f\xe9\xbf:\xb0c\xa3\x91\xb5\x1d\x89Mm\xab\x94N+\x95J\
\xc9\xf3\\e\xd2\x9e.\xf4\x1e\x92V\xcfJ\xb5>\xd9W\xd7\x14\x1cM)\x9a\x9dV2\xc2\
#*\x95\x8c$?\x81\'\xc9\x95\x8c\x91\x0ex\xea\xbfx\\Z\xbc \xd5\xafH\xd5\x01\
\x95n\x1cWx\xfb\x86\xf6eap\xb0O\xa5\x12\xb2\x16I\tZ\x8e\xb4\xfe\x83\xb4R\x90\
\xde\xff(\xfb\xe6\x8aJ7\x8fj\xf0\xea\xc5\xdd<8;?\x9dz\x1e\x19\xd7\x1d\xa1\
\xb7\x17\xc6\xc6`n\x0e\xe2\xa6K\xdct\x98{\xb7\xce\xd8\xd3\x7f\xe9\x1dz\x81{\
\xb0\x8f\xa9\xd9\xb7fw,\xbe\x8dg\x14E\n\xc3\xbb\xca\xe7\x8f\xc8\xf7\x90\xef\
\xa1\xfc\x99\xc3\n\xcb\x7f(\xfa{\xf6\xbb8\x7f\x01 \xf1c\xdaX\x1e\x99\x02\x00\
\x00\x00\x00IEND\xaeB`\x82' 

def getSmilesBitmap():
    import wx
    return wx.BitmapFromImage(getSmilesImage())

def getSmilesImage():
    import wx
    import cStringIO
    stream = cStringIO.StringIO(getSmilesData())
    return wx.ImageFromStream(stream)

#----------------------------------------------------------------------
def getSmallUpArrowData():
    return \
'\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x10\x00\x00\x00\x10\x08\x06\
\x00\x00\x00\x1f\xf3\xffa\x00\x00\x00\x04sBIT\x08\x08\x08\x08|\x08d\x88\x00\
\x00\x00<IDATx\x9ccddbf\xa0\x040Q\xa4{h\x18\xf0\xff\xdf\xdf\xffd\x1b\x00\xd3\
\x8c\xcf\x10\x9c\x06\xa0k\xc2e\x08m\xc2\x00\x97m\xd8\xc41\x0c \x14h\xe8\xf2\
\x8c\xa3)q\x10\x18\x00\x00R\xd8#\xec\x95{\xc4\x11\x00\x00\x00\x00IEND\xaeB`\
\x82' 

def getSmallUpArrowBitmap():
    import wx
    return wx.BitmapFromImage(getSmallUpArrowImage())

def getSmallUpArrowImage():
    import wx
    import cStringIO
    stream = cStringIO.StringIO(getSmallUpArrowData())
    return wx.ImageFromStream(stream)

#----------------------------------------------------------------------
def getSmallDnArrowData():
    return \
"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x10\x00\x00\x00\x10\x08\x06\
\x00\x00\x00\x1f\xf3\xffa\x00\x00\x00\x04sBIT\x08\x08\x08\x08|\x08d\x88\x00\
\x00\x00HIDATx\x9ccddbf\xa0\x040Q\xa4{\xd4\x00\x06\x06\x06\x06\x06\x16t\x81\
\xff\xff\xfe\xfe'\xa4\x89\x91\x89\x99\x11\xa7\x0b\x90%\ti\xc6j\x00>C\xb0\x89\
\xd3.\x10\xd1m\xc3\xe5*\xbc.\x80i\xc2\x17.\x8c\xa3y\x81\x01\x00\xa1\x0e\x04e\
\x1d\xc4;\xb7\x00\x00\x00\x00IEND\xaeB`\x82" 

def getSmallDnArrowBitmap():
    import wx
    return wx.BitmapFromImage(getSmallDnArrowImage())

def getSmallDnArrowImage():
    import wx
    import cStringIO
    stream = cStringIO.StringIO(getSmallDnArrowData())
    return wx.ImageFromStream(stream)


if __name__ == "__main__":
    main()



