#!/usr/bin/perl
# SUMI Sender (server/sharerer)

# This is the Perl version. Its very informative, but
# suffers from several nonimplementations:
# - doesn't use raw sockets (C++ version does)
# - doesn't drop root privs (C++ version does)
# - doesn't verify src ip (C++ version does) 
#   (it would always fail, anyways)
# Update: the Python version addresses these limitations, too

use Socket;
use Net::IRC;
use Digest::MD5 qw/md5_base64 md5_hex/;
use MIME::Base64;
use Time::HiRes qw(time usleep);

use strict;
use warnings;

our ($irc_nick, $irc_server, $irc_port, $irc_name, $channel, @files, $mss);
our ($irc, $conn, %clients);

our ($localaddr) = "10.0.0.1";

if ($> != 0) {
   warn "Not running as root, trying to...";
   system("sudo perl $0");
   exit;
}

$irc_nick = "sumiserv";           # Your IRC nickname for serving
$irc_server = "ggrn.de.eu.deepirc.net";        # IRC server. Set this to 127.0.0.1 for IIP
$irc_port = 6667;
$irc_name = $irc_nick;
$channel  = "#sumi";              # IRC channel to join

@files = ("data.txt", "/dev/urandom", "1mb");

$mss = 1472;        # Max Seg Size (MTU-28) to 578, if >, will be trunc'd

$irc = new Net::IRC;
print "Connecting to IRC...";
$conn = $irc->newconn(Nick    => $irc_nick,
                      Server  => $irc_server,
                      Port    => $irc_port,
                      Ircname => $irc_name,
                      LocalAddr=> $localaddr);
if (!$conn) { die "Error connecting: $!"; }
print "OK\n";
$conn->add_global_handler("376", \&on_connect);
$conn->add_handler("msg", \&on_msg);

$irc->start();

sub on_msg
{
    my ($self, $evt) = @_;
    my ($msg) = $evt->{args}->[0];
    my ($from, $nick) = ($evt->{from}, $evt->{nick});

    print "$nick: $msg\n";

    if ($clients{$nick}{AUTH}) {
        transfer_control($nick, $msg);    # Use shorter protocol
    }

    # sumi send: client tells us file she wants and her IP
    if ($msg =~ 
m/^sumi send ([^\t]+)\t([^\t]+)\t([^\t]+)\t([^\t]+)\t([^\t]+)\t([^\t]+)\t([^\t]+)/) 
    {
        my ($file, $offset, $their_ip, $their_port, $their_mss, $prefix,
            $latency) = ($1, $2, $3, $4, $5, $6, $7);
        my ($key);

        # Make sure the filename/pack number is valid
        # FOR NOW, THE FILENAME IS A PACK NUMBER - I.E., #1
        $file = substr($file, 1) if substr($file, 0, 1) eq '#';
        $file-- if ($file + 0) eq $file;    # Make 1-based be 0-based
        
        $file = $files[$file];

        $conn->privmsg($nick, "error: no such pack number/file $file"), return
            unless defined($file) && -e $file;


        # Prefix is base64-encoded for IRC transport (3 bytes -> 4 bytes)
        # Note: There is no need to use Base85 - Base94 (RFC 1924) because
        # it can increase by a minimum of one byte. yEnc may work, but I
        # doubt its worthwhile for a lousy 3 bytes. Base64 is perfect for this.
        $prefix = decode_base64($prefix);

        #print "$nick claims her ip is $their_ip, wants $file\n";

        # Limit minimum MSS to 256 (in reality, it has a minimum of ~548)
        # This is done to block an attack whereby the attacker chooses a MSS
        # equal to that of our nickname, so thats all that fits in the packet.
        # She then can hash our nick and verify it, without verifying the UDP
        # transmission. If we allow this to happen, then we may be sending UDP
        # packets to a host that didn't request them -- DoS attack. Stop that.
        #     256 MSS has to be small enough for anybody.
        if ($their_mss < 256) {
            $conn->privmsg($nick, "error: MSS $their_mss is too small <256");
            return;
        }

        # Limit length of prefix, so clients can't fill up the auth packet with
        # data completely of choosing circumventing the auth process.
        if (length($prefix) > 100) {
            $conn->privmsg($nick, "error: prefix is too large >100");
        }

        # Generate a random key the size of the MSS. Send this to the client,
        # and have them send a hash back through IRC. Check connection.
        # Build it completely instead of using datapkt() so we can hash it all
        #$key = $irc_nick . "\t";       # include IRC nick in packet too
        $key = $prefix;          # Client-generated prefix to verify us
        $key .= "\0";           # Seqno placeholder (2 * 24)
        #$key .= chr rand 255 for 1..($their_mss - length($irc_nick) - 1 - 5);
        $key .= chr rand 255 for 1..($their_mss - length($prefix) - 1);

        if (length($key) != $their_mss) {
            die "bad key generation: " . length($key) . " != $their_mss";
        }

        # Keep track of this     
        $clients{$nick} = { MSS => $their_mss,
                            #HASH => md5_base64($key),
                            KEY => $key,     # ^ don't know hash until MSS
                            PREFIX => $prefix,
                            IP => $their_ip,
                            PORT => $their_port,
                            FILE => $file,
                            OFFSET => $offset,
                            LATENCY => $latency };
        print "$nick request: MSS=$clients{$nick}{MSS} " .
              "IP=$clients{$nick}{IP}:$clients{$nick}{PORT} ".
              "KEY=@{[ length $clients{$nick}{KEY} ]} bytes PREFIX=" .
              encode_base64($clients{$nick}{PREFIX}, '')."\n";

        my $err = udp_send("$their_ip:$their_port", $key, 0xffff);
        if ($err) {
            $conn->privmsg($nick, "udp error: $err");
            return;
        }
    } elsif ($msg =~ m/^sumi auth ([^\t]+)\t([^\t]+)\t([^\t]+)/) {   # authenticating
        my ($their_mss, $asrc, $hash) = ($1, $2, $3);
        my ($filename, $offset, $size, $them);

        print "Verifying authenticity of client $nick...";
        if ($clients{$nick}{MSS} != $their_mss)
        {
            $conn->privmsg($nick, "error: MSS too small $their_mss"), return if
                $their_mss < 256;
            print "Downgrading MSS of $nick: " .
                  "$clients{$nick}{MSS}->$their_mss\n";
            $clients{$nick}{MSS} = $their_mss;
        }

        #$conn->privmsg($nick, 
        #    "error: MSS mismatch $clients{$nick}{MSS} != $their_mss"), return
        #    if $clients{$nick}{MSS} != $their_mss;
        # The client may have truncated the datagram to match their MSS
        my $derived_hash = 
                      md5_hex(substr($clients{$nick}{KEY}, 0, $their_mss));
        # (Note: this was base64, now its hex)

        print "$nick says we sent from $asrc\n";

        $conn->privmsg($nick, "error: $derived_hash != $hash"), return
            if $derived_hash ne $hash;
        #$conn->privmsg($nick, "error: $clients{$nick}{HASH} != $hash"), return
        #    if $clients{$nick}{HASH} ne $hash;
        print "OK\n";

        $filename = $clients{$nick}{FILE};
        $offset = 0;       # TODO: support resuming, block level offsets
        $size = -s $filename;
        $their_mss = $clients{$nick}{MSS};
        #$prefix = $clients{$nick}{PREFIX};

        $clients{$nick}{AUTH} = 1;
        $conn->privmsg($nick, "sumi start $filename\t$offset\t$size");
    }
}

# Construct and send a data transfer packet
sub datapkt
{
    my ($nick, $seqno, $data) = @_;
    my ($srcport, $err, $prefix);

    $prefix = $clients{$nick}{PREFIX};

    die "mkdatapkt: prefix != 3 " if length($prefix) != 3;
    die "seqno: >= 2**24" if $seqno >= 2**24;

    ###print "About to send ", length($data), " bytes\n";
    $srcport = ($seqno & 0xffff00) >> 8;
    $srcport = 0xffff if $srcport == 0;    # Can we do srcport = 0??

    # For some reason, $them gets clobbered; reset it
    my $them = "$clients{$nick}{IP}:$clients{$nick}{PORT}";

    usleep($clients{$nick}{LATENCY});

    $err = udp_send($them, $prefix . chr($seqno & 0xff) . $data, $srcport);
    die "datapkt: $err" if $err;

    return length($data);
}

# Handles messages during file transfer
sub transfer_control
{
    my ($nick, $msg) = @_;
    my ($filename, $offset, $size, $their_mss, $prefix);

    $filename = $clients{$nick}{FILE};
    $offset = 0;       # TODO: support resuming, block level offsets
    $size = -s $filename;
    $their_mss = $clients{$nick}{MSS};
    $prefix = $clients{$nick}{PREFIX};

    ##print "(XFER) $nick: $msg\n";

    if  ($msg =~ m/^n(\d+),?(.*)/) {     # Next packets/neg ack, windowed
        my ($rwinsz) = $1; 
        my (@resend) = split /,/, $2;
        print "RWIN=$rwinsz RESEND=@resend\n";

        if (!$clients{$nick}{SEQNO}) {    # No seqno, first. Set it up
            $clients{$nick}{SEQNO} = 1;
            open($clients{$nick}{FH}, "<$filename") || die "cannot open $filename: $!";
        }
        my $fh = $clients{$nick}{FH};

        local $/ = \($their_mss - 4);

        # Now that resent packets are sent, send the normal, fresh packets,
        # up to RWIN size. We have to lower the RWIN here so that we don't
        # exceed it by sending more than the client can accept.
        $rwinsz -= @resend;

        # If any @resend packets are listed, send them first
        if (@resend) {
            for my $no (@resend) {
                seek $fh, ($no - 1) * ($clients{$nick}{MSS} - 4), 0;
                my $blk = <$fh>;
                datapkt($nick, $no, $blk);
                print "Resent packet $no on request\n";
            }
        }


        my $blk;
        for (1..$rwinsz)     # send up to RWIN packets
        {
            seek $fh, ($clients{$nick}{SEQNO} - 1) * 
                      ($clients{$nick}{MSS} - 4), 0;

            $blk = <$fh>;

            last if !defined($blk);       # EOF

            if ($clients{$nick}{SEQNO} == 25) {
               print "DROPPING PACKET\n";
            } else {
            datapkt($nick, $clients{$nick}{SEQNO}, $blk); 
            }
            ###print "UDP'd $clients{$nick}{SEQNO} to $nick\n";
     
            $clients{$nick}{SEQNO}++;
        }
        if (!defined($blk)) {
            print "Transfer finished to $nick!\n";
        }

    # "k" = TFTP-like transfer, each packet is ack'd
    } elsif ($msg eq 'k' && !$clients{$nick}{SEQNO}) {
        my ($fh);

        $clients{$nick}{SEQNO} = 1;
        # Now begin transfer
        my $them = "$clients{$nick}{IP}:$clients{$nick}{PORT}";   # shortcut
    
        # Data packet payload: <3-byte-prefix><1-byte-seqno-low-byte>
        #  The seqno is 24 bits (for 8-16GB max), low bits are ^^^, high
        #  sixteen bits are stored in the local source port number (heh)

        open($fh, "<$filename") 
            || die "cannot open $filename: $!";
        $clients{$nick}{BLOCKSIZE} = $their_mss - 4;

        local $/ = \($their_mss - 4);

        my $seqno = 1;
        $clients{$nick}{FH} = $fh;
        datapkt($nick, $clients{$nick}{SEQNO}, scalar <$fh>);
   } elsif ($msg =~ m/^k(.*)/) {    # "k" acknowledgement, send next packet
        #print "Got ack for $1, sending $1+1...";
        local $/ = \($clients{$nick}{MSS} - 4);
        my $fh = $clients{$nick}{FH};
        # Horrible; this code doesn't even care what the client said. Obsolete.
        # Still may be good to leave this around; for testing purposes
        datapkt($nick, ++$clients{$nick}{SEQNO}, scalar <$fh>);
        #print "OK\n";
   }
}

sub on_connect
{
    my $self = shift;

    print "Joining $channel...";
    $self->join($channel);
    print "OK\n";
    $self->privmsg($channel, "sender ok");
}

# Return our local, bindable, address; also, $proto
#sub get_my_addr
#{
#   my ($name, $aliases, $proto, $type, $len, $myaddr);
#
#   ($name,$aliases,$proto) = getprotobyname('udp');
# 
#   chop(my $hostname = `hostname`);
#   ($name,$aliases,$type,$len,$myaddr) = gethostbyname($hostname);
#
#   return ($myaddr, $proto);
#}

# NOTE: You need ROOT ACCESS or to set net.inet.ip.portrange.reservedhigh to 0
# in FreeBSD: sysctl -w net.inet.ip.portrange.reservedhigh=0
sub udp_send
{
# based on http://cayfer.bilkent.edu.tr/~cayfer/ctp208/socket/
my ($dest, $data, $srcport) = @_;
my ($dest_addr, $port) = split /:/, $dest;
my (@dest_addr) = split /\./, $dest_addr;
my ($sockaddr, $name, $aliases, $proto, $type, $len);
my ($me, $them, $sent);
$sockaddr = "S n a4 x8";

(undef, undef, $proto) = getprotobyname("udp");

$me   = pack($sockaddr,&AF_INET, $srcport,     pack("C4", split /\./, $localaddr));
$them = pack($sockaddr,&AF_INET, $port,        pack("C4", @dest_addr));
 
socket(S, &AF_INET, &SOCK_DGRAM, $proto) || die $!;

setsockopt(S,&SOL_SOCKET,&SO_BROADCAST,1) || die $!;
setsockopt(S,&SOL_SOCKET,&SO_REUSEADDR,1) || die $!;
setsockopt(S,&SOL_SOCKET,&SO_REUSEPORT,1) || die $!;

bind(S, $me) || warn "bind to $name:$srcport: $!";    # set source port

if (!send(S,$data,0,$them))
{
    return "fail: :$srcport->$dest @{[ length $data ]} bytes, $!";
}

}

