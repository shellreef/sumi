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

def transport_init():
    global g_mem, g_mIRC

    g_mem = mmap.mmap(0, 4096, "mIRC")
    try:
        g_mIRC = win32gui.FindWindow("mIRC", None)
    except:
        log("SYS:An error occured while trying to locate mIRC. Is mIRC"+\
                "running?")
        sys.exit(-1)
    log("Located mIRC, running...")


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

def recvmsg(callback):
    """Capture receiving messages using pcap. Won't work with encrypted IRC, 
    or ports outside 6000-8000."""
    def decoder(pkt_data):
        return decode_irc(get_tcp_data(pkt_data))
    
    # Ports 6660-6669, 7000. Fairly conservative range. Can't filter PRIVMSG,
    # because its location within TCP packet varies with a source prefix.
    filter = "tcp and ("
    s = 6660
    e = 6669
    if cfg.has_key("irc_port_range"):
        # Some IRC servers use odd ports, allow configurable range
        s, e = map(int, sumiserv.cfg["irc_port_range"].split("-"))
    for i in range(6660, 6669):
        filter += "port %s or " % i
    filter += "port 7000)"
    # Never returns
    capture(decoder, filter, callback)

def decode_irc(data):
    """Decode IRC data, returning nickname and message of private messages."""
    if len(data) == 0 or data[0] != ":" or not " " in data: 
        return (None, "not incoming")
    source, cmd, args = data.split(" ", 2)
    if cmd != "PRIVMSG":
        return (None, "not message")
    nick, host = source[1:].split("!")
    dest, msg = args.split(" ", 1)
    if msg[0] != ":":
        return (None, "unexpected missing :") 
    return (nick, msg[1:])


