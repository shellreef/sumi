# Created:20040805
# By Jeff Connell

# Windows AOL Instant Messenger

# Tested on 5.5.3595, 5.5.3292

import win32api
import win32gui
import win32con
import urllib
import time

def transport_init():
    print "Initializing WinAIM transport"

def sendmsg(nick, msg):
    # segment() is provided by the framework to split up a message
    # and call sendmsg_1 if needed. Do this if transport has msg len limits.
    segment(nick, msg, 500, sendmsg_1)

# Return a list of open IM window handles
def get_aim_wins(filter):
    allwins = []
    aimwins = []
    win32gui.EnumWindows(lambda x,y: allwins.append(x), [])
    for w in allwins:
        # Look for class AIM_IMessage
        if win32gui.GetClassName(w) == 'AIM_IMessage' and filter(w):
            aimwins.append(w)
    return aimwins

def sendmsg_1(nick, msg):
    #print "Trying to send %s to %s", msg, nick

    im = 0

    # See if there is already an AIM window for this user open
    aimwins = get_aim_wins(lambda x: \
        win32gui.GetWindowText(x).find(" - Instant Message") != -1)
    #print aimwins

    for aimwin in aimwins:
        title = win32gui.GetWindowText(aimwin)
        # to : from - Instant Message OR to - Instant Message (older AIMs)
        if (title.find(" : ") != -1):
            to = title[0:title.find(" : ")]
        else:
            to = title[0:title.find(" - ")]

        if (to == nick):
            im = aimwin
            break

    if not im:
        # Not already open, have to create it. Before any messages are sent
        # (goim only types the message - doesn't send it), AIM windows have
        # a title of "Instant Message", plain. Close any of these to prevent
        # confusion in finding our new AIM window after the ShellExecute.
        aimwins = get_aim_wins(lambda x: \
            win32gui.GetWindowText(x) == "Instant Message")
        for aimwin in aimwins: 
            win32gui.SendMessage(aimwin, win32con.WM_CLOSE, 0, 0)
        # Open the window
        url = "aim:goim?" + urllib.urlencode({"screenname": nick})
        win32api.ShellExecute(0, "", url, None, None, win32con.SW_SHOW)

    # Type out the message. This is aim URL style, don't use it anymore
    # because although it supports HTML, it steals focus.
    #url = "aim:goim?" + urllib.urlencode({"screenname": nick, "message": msg})
    #win32api.ShellExecute(0, "", url, None, None, win32con.SW_HIDE)

    # Need to locate actual AIM window to press Enter
    wait = 0
    while not im and wait < 1000:
        # Since there wasn't an existing AIM window, look for an untitled one
        aimwins = get_aim_wins(lambda x: \
            win32gui.GetWindowText(x) == "Instant Message")
        time.sleep(0.01)
        if len(aimwins) == 0:
            continue
        im = aimwins[0] 
        wait += 1

    if not im:
        print "couldn't find AIM window!"
        return -1

    # Find the input control
    kids = []
    found_atewin = 0
    txtwin = 0
    win32gui.EnumChildWindows(im, lambda x,y: kids.append(x), 0)
    for kid in kids:
        #print "%x" % kid
        if 1 and win32gui.GetWindowText(kid) == "AteWindow":
            found_atewin = 1
            kids2 = []
            win32gui.EnumChildWindows(kid, lambda x,y: kids2.append(x), 0)
            # Has two children - a CBClass and Ate32Class
            if len(kids2) != 2:
                continue

            if win32gui.GetClassName(kids2[1]) != "CBClass":
                print "The second child window wasn't a CBClass. Unexpected."
                print "AIM may have changed. If so please edit the code."
                return -3
  
            if win32gui.GetClassName(kids2[0]) != "Ate32Class":
                print "First child window wasn't an Ate32Class. The required"
                print "window is missing. AIM have changed. Fatal error."
                return -4
          
            txtwin = kids2[0] 
            break          
    if not found_atewin:
        print "Sorry couldn't find AteWindow. AIM might have changed "
        print "windows, rendering this program incompatible."
        return -2
    if not txtwin:
        print "Somehow txtwin wasn't found."
        return -5

    # Type out the message. WM_CHAR doesn't steal focus, but it can't
    # handle some characters and doesn't allow HTML.
    for ch in msg:
        win32api.SendMessage(txtwin, win32con.WM_CHAR, ord(ch), 0)

    win32api.SendMessage(txtwin, win32con.WM_KEYDOWN, win32con.VK_RETURN, 0)
    win32api.SendMessage(txtwin, win32con.WM_KEYUP, win32con.VK_RETURN, 0)

# that's it! but receiving is 20x more complicated 
