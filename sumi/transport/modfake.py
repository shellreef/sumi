# Created:20040711
# By Jeff Connelly

# Fake transport module. Can use this for debugging or the basis for your
# own transport module. Enjoy. P.S.: Handshaking will always timeout here.

def transport_init():
    print "Initializing fake transport"

def sendmsg(nick, msg):
    # segment() is provided by the framework to split up a message
    # and call sendmsg_1 if needed. Do this if transport has msg len limits.
    segment(nick, msg, 500, sendmsg_1)

def sendmsg_1(nick, msg):
    print "(fake) <%s>%s" % (nick, msg)

