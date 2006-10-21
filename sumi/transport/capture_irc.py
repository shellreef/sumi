# Created:20050806
# By Jeff Connelly

# Capture IRC messages using pcap

# Currently used by mirc and xchat transports, but any IRC transport could
# use this.

def generic_irc_recvmsg(callback, transport_name, server=True):
    """Capture receiving messages using pcap. Won't work with encrypted IRC, 
    or ports outside 6000-8000."""
    def decoder(pkt_data):
        if decode_irc and get_tcp_data:
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

    callback("(transport_ready)", transport_name)
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

