# Created:20040130
# By Jeff Connelly

# mIRC module

# If you get "win32api" not found when loading, install Win32 modules.
# They're included in ActivePython by default.
import win32api
import win32con
import win32gui
import mmap
import sys

global recvmsg

def transport_init():
    global g_mem, g_mIRC, recvmsg

    g_mem = mmap.mmap(0, 4096, "mIRC")
    try:
        g_mIRC = win32gui.FindWindow("mIRC", None)
    except:
        log("SYS:An error occured while trying to locate mIRC. Is mIRC"+\
                "running?")
        sys.exit(-1)
    log("Located mIRC, running...")

    # Our transport_init is called after all these calls were imported
    import capture_irc
    recvmsg = capture_irc.recvmsg
    capture_irc.capture = capture
    capture_irc.cfg = cfg
    capture_irc.get_tcp_data = get_tcp_data


def sendmsg(nick, msg):
    #sendmsg_1(nick, msg)
    # 550 is max length, segment at that point
    segment(nick, msg, 550, sendmsg_1)

#def sendmsg_with_segment(nick, msg):
#    n = 0
#    # Length of each segment, to overcome limitations of IRC privmsg's, the
#    # msg will be split into segments within range of privmsg limit. The 
#    # last segment has no ">" prefix, other segments do.
#    MAX_LEN = 550#3#512 - len(":PRIVMSG") - len(nick)
#    prefix = ">"
#    while len(msg[n:n+MAX_LEN]):
#        if n + MAX_LEN >= len(msg):
#            prefix = ""
#        sendmsg_1(prefix + msg[n:n+MAX_LEN])
#        #print(prefix + msg[n:n+MAX_LEN])
#        n += MAX_LEN 

def sendmsg_1(nick, msg):
    global g_mem, g_mIRC

        # MAX IRC PRIVMSG IN XCHAT: 452 in #sumi, 454 in #a (??) 462 in #a*31
        # ON NGIRCD: COMMAND_LEN - 1, is 513-1 is 512. Room for PRIVMSG+nick.
        # ":jeff PRIVMSG " = 14

    g_mem.seek(0)
    g_mem.write("/msg %s %s" % (nick, msg) + "\0" * 100)
    win32api.SendMessage(g_mIRC, win32con.WM_USER + 200, 0, 0)

