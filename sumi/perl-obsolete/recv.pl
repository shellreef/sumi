#!/usr/bin/perl
# Created:2003-08-03
# By Jeff Connelly
#
# SUMI recv.pl 
#
use IO::Socket;
use IO::Select;
use Net::IRC;
use Digest::MD5 qw(md5_base64 md5_hex);
use MIME::Base64;
use Fcntl qw(SEEK_SET);
use Time::HiRes qw(usleep time);

use strict;

our ($irc_nick, $irc_server, $irc_port, $irc_name, $channel, $mss, $irc, $conn);
our ($pid, $pid2, $myip, $latency, $localaddr);

# Your IP and your port - these must be INTERNET ACCESSIBLE! That means use
# your public IP, and forward a UDP port on your router.
our ($myip, $myport) = ("4.34.151.113", "1170");

# Your local IP to bind to. This can be your private IP if you have one.
# Otherwise it can be the same as $myip.
$localaddr = $myip;

# XXX: Merge "filemap" with %rwin, $lostpktcount, %missed! Is redundant.
# Update: merged, no more %rwin / %missed
# Maybe also merge with %senders, if can.
our (%senders, %filemap, $START, $rwinsz, $lostpktcount, $chankey);
our ($SUMIHDRSZ) = 6;

$irc_nick = "sumiget";
$irc_server = "irc.sw33tn3ss.net";
$irc_port = 6667;
$irc_name = $irc_nick;
$channel = "#sumi";
$chankey = "riaa";

# MSS = MTU - IP_header(20 bytes) - IP header(8 bytes)
# Most minimal: MTU 552, MSS=524 (still not that bad)
# MIN: Hosts required to handle 576 byte IP datagrams, 548 byte payload
# With VLAN/tunnel headers, MSS<=1450
# On Ethernet, MTU=1500, MSS=1472
# MAX: 65535 - 28 = 65,507 (excluding jumbo payload option)
# We don't want fragmentation -- makes packets much more fragile.

# IMPORTANT: UDP MSS is not TCP MSS! UDP MSS is 12 bytes larger because of
# UDP's smaller headers (8 vs 20). Keep this in mind for best efficiency.

#$mss = 1492 - 28;      # Ethernet w/ PPPoE
$mss = 1500 - 28;      # Ethernet 
#$mss = 4352 - 28;      # FDDI
#$mss = 9244 - 28;      # Loopback on many OS's (FreeBSD, OSF/1)

# RWIN - suggested 3x-4x MSS for TCP, or 8x-10x MSS for file transfer for TCP
# Here, this is the number of PACKETS we want to be sent before NACKing
# Set this to as high as you can without having lots of packet loss!
# The lower it goes, the more the latency of IRC will affect the bandwidth
$rwinsz = 15;

# Latency - how long, in microseconds, sender should wait between packets
# Set this to a value that does not exceed your bandwidth.
$latency = 30;

$lostpktcount = 0;

$irc = new Net::IRC;
print "Connecting to IRC...";
$conn = $irc->newconn(Nick    => $irc_nick,
                      Server  => $irc_server,
                      Port    => $irc_port,
                      Ircname => $irc_name,
                      LocalAddr=> $localaddr);
print "OK\n";

$conn->add_global_handler("376", \&on_connect);
$conn->add_global_handler("353", \&on_namreply);
$conn->add_global_handler("msg", \&on_msg);
$conn->add_global_handler("366", sub { print "*** End of names list\n" }); 

if ($pid = fork) {
    print "THREAD 1 - UDP SERVE\n";
    my ($hostname) = `hostname`;
    chomp($hostname);
    udp_serve($myport, $hostname, \&handle);
} else {
    if ($pid2 = fork) {
        print "THREAD 2 - IRC CLIENT\n";
        $irc->start();
    } else {
        print "THREAD 3 - USER INPUT\n";
        user_input();
    }
}

sub on_msg
{
    my ($self, $evt) = @_;
    my ($arg) = $evt->{args}[0];
    my ($nick) = $evt->{nick};
    print "$nick: $arg\n";

    # Senders rarely communicate with us through IRC because they have their
    # UDP channel, but for the initial start packet, they do. Mostly errors
    # are sent through
    #if ($arg =~ m/sumi start ([^\t]+)\t([^\t]+)\t([^\t]+)/) {
    if ($arg =~ m/sumi start (.*)/){
        #my ($filename, $offset, $size) = ($1, $2, $3);
        my (%args) = parse_args($1);
        my ($filename, $offset, $size) = ($args{f}, $args{o}, $args{l}); 
       
        load_senders();

        if ($senders{$nick}) {
            #$conn->privmsg($nick, "k");   # Kick it off, TFTP-style
            #print "Ack'd $nick for $filename,$offset,$size\n";
            #return;

            $conn->privmsg($nick, "n$rwinsz");
            print "Starting n$rwinsz $nick for $filename,$offset,$size\n";
            print "Expecting packets $senders{$nick}{AT} ~ ", 
                  $senders{$nick}{AT} + $rwinsz - 1, "\n";

        } else {
            print "ERROR: $nick isn't known, trying to sumi start!\n";
            print "Senders: ", join("\n", keys %senders), "\n";
        }
    }
}

sub user_input
{
    print "Started user input thread... you may now type.\n";
    while()
    {
        $_ = <STDIN>;
        chomp;
        last if !defined;   # undefined string, EOF
        next if !length;    # empty string, ignore
        if (m/^\/names/) { 
            $conn->names($channel);
        } elsif (m/^\/get\s+(\S+)\s+(\S+)/) {
            request($1, $2);
        } elsif (m/^[^\/]/) {
            $conn->privmsg($channel, $_);
        }
    }
}

# Request a file to be sent
sub request
{
    my ($server_nick, $file, $offset) = @_;
    my ($prefix);

    # How should resuming work? Not all may be complete. Holes.
    #if (length($server_nick) < 5) {
    #    die "$server_nick is too short of a nickname";
    #}

    print "Get file |$file| from |$server_nick|\n";

    # Five random ASCII bytes to authenticate the server
    #$prefix .= chr(rand(93) + 33) for 1..5;
    # Three random bytes of anything, will be b64-encoded for IRC
    $prefix .= chr rand 255 for 1..3;

    # not a 
    # THREAD SYNC PROBLEM - (fixed by files) - this is called in the input fork,
    #   (%senders is written to), but it is read in the UDP read fork    
    #UPDATE 20040117: No this isn't a problem with threads, its a problem with
    # using multiple processes (forked) to be like threads, but its not threads
    # Neither is it portable. Perl can do threads, but its highly alpha, so
    # I'm switching to Python and using its interface to pthreads, much nicer.
    $senders{$server_nick} = { FILE => $file,
                               PREFIX => $prefix,
                               AT => 1,       # seqno's are 1-based!
                             };
    save_senders();

    $offset = 0;

    #$conn->privmsg($server_nick, 
    #    "sumi send $file\t$offset\t$myip\t$myport\t$mss\t" . 
    #    encode_base64($prefix, '') . "\t$latency");
    $conn->privmsg($server_nick, "sumi send ".
        make_args(f=>$file, o=>$offset, i=>$myip, n=>$myport,
                  m=>$mss, p=>encode_base64($prefix,""), l=>$latency));
}

sub on_namreply
{
    my ($self, $evt) = @_;
    my ($mynick, undef, $thischan, $names) = @{$evt->{args}};

    print "Names on $thischan: $names\n";
}

sub on_connect
{
    my $self = shift;
    print "Joining $channel...";
    $self->join($channel, $chankey);
    print "OK\n";
}

sub save_senders
{
    #print "@@@ ADDED SENDER: $server_nick @@@\n";
    unlink("senders.txt");
    open(SF, ">>senders.txt") || die "senders.txt: $!";
    foreach my $nick (keys %senders) {
        #print SF "$server_nick\t$file\t" . encode_base64($prefix, '') . "\n";
        print SF "$nick\t$senders{$nick}{FILE}\t" . 
              encode_base64($senders{$nick}{PREFIX}, '') .
              "\t$senders{$nick}{AT}\n";
    }
    close(SF);
}

sub load_senders
{
    # Authentication packet begins with server's IRC nickname + a tab
    if (open(SF, "<senders.txt")) {   # New senders to auth
        while(<SF>) {
            chomp;
            my ($nick, $file, $prefix, $at) = split /\t/;
            $prefix = decode_base64($prefix);
            my $x = $prefix;
            $x =~ s/(.)/sprintf"%.2x ",ord($1)/ge;
            $senders{$nick} = { FILE => $file, PREFIX => $prefix, AT => $at };
        }
        close(SF);
        #unlink("senders.txt");
    }
}

# Handle incoming UDP
sub handle
{
    my ($src, $srcport, $dst, $dstport, $data) = @_;
    my ($srcip) = join ".", unpack "C4", $src;
    my ($dstip) = join ".", unpack "C4", $dst;
    my ($len) = length($data);
    my ($seqno, $known_key, $done);

    load_senders();
    #print "@@@ READING SENDERS: ", keys %senders, " @@@\n";

    # Find random prefix we sent associated with nick
    my ($prefix, $nick);    # Scoped here so they'll be retained upon loop exit
    foreach my $anick (keys %senders) {
        $prefix = $senders{$anick}{PREFIX};
        next if length($prefix) == 0;
        $nick = $anick;
        $known_key = 1, last if index($data, $prefix) == 0;
    }
    print"$srcip:$srcport($nick) -> $dstip:$dstport sent $len bytes($seqno)\n";

    if (!$known_key) {
        print "Ignoring datagram with unrecognized key: " ,
              " $srcip:$srcport -> $dstip:$dstport\n";
        my $got = substr($data, 0, 3);
        $got =~ s/(.)/sprintf"%.2x ",ord($1)/ges;
        my $want = $senders{"sumiserv"}{PREFIX};
        $want =~ s/(.)/sprintf"%.2x ",ord($1)/ges;
        print "got=$got, want=$want\n";
        return;
    }

    $srcport = 0 if $srcport == 0xffff;   # not really needed anymore

    # Derive sequence number from source port and extra byte
    # This is what sender.pl expects, but its a bad idea. Some hosts mangle it.
    # (( PAT - Port Address Translation, closely related to NAT ))
    #$seqno = ord(substr($data, 3, 1)) + $srcport * 0x100;
    #COMPAT NOTE: This new method below uses 3 bytes for the seqno, in the
    #payload portion. This means the SUMI header is 6 bytes, not 4.
    #$seqno = ord(substr($data, 3, 1)) +
    #        (ord(substr($data, 4, 1)) *    0x1_00) +
    #        (ord(substr($data, 5, 1)) * 0x1_00_00);
    #COMPAT NOTE 2: Starting with the Python version the seqno is in network
    # order, so a null can be appended/removed for conversion to a long.
    # THEREFORE, if trying to get sumiserv C++ to work, change the endian
    $seqno = unpack("N", ("\0" . substr($data, 3)));

    if ($seqno == 0) {        # all 0's = auth packet
        #my ($nick) = $data =~ m/^([^\t]+)/;   # nick<tab><prefix><data>
        #my ($prefix) = $data =~ m/^[^\t]+\t(.*)/s;
        # COMPAT NOTE: The Perl sender.pl expects base64'd hash
        #my ($hash) = md5_base64($data);       # key is all of data, hash it
        my ($hash) = md5_hex($data);     # HEX

        print "Got auth packet from $srcip:$srcport! for $nick\n";
        print "Verifying prefix (authenticity of server)...";
        #print "DEBUG: hex hash=" . md5_hex($data) . "\n";
        #if (index($prefix, $senders{$nick}{PREFIX}) == 0) {
        # Does this ever fail??
        if (index($data, $prefix) == 0 && $len >= length($prefix)) {
            print "OK\n";
        } else {
            die "failed! $senders{$nick}{PREFIX}\n";
        }
        if ($mss != $len) {
            print "WARNING: Downgrading MSS $mss->$len, maybe set it lower?\n";
            $mss = $len;
            if ($mss < 256) {
                print "MSS is extremely low ($mss), quitting\n";
                exit;
            }
        }
        print "Sending sumi auth $mss\t$srcip\t$hash to $nick\n";

        # COMPAT NOTE: Perl sender doesn't expect srcip field, C++ demands it
        # COMPAT NOTE 2: new arg format, make_args
        #$conn->privmsg($nick, "sumi auth $mss\t$srcip\t$hash");
        $conn->privmsg($nick, "sumi auth ".make_args
            (m=>$mss, s=>$srcip, h=>$hash));

    } else {
        # Prefix has been checked, seqno calculated, so just get to the data
        $data = substr($data, $SUMIHDRSZ); 

        # All file data is received here
        my $off = ($seqno - 1) * ($mss - $SUMIHDRSZ);
        my $len = length($data);

        if (!$filemap{$nick}{FH}) {
            print "Opening tempout for $nick...";
            open($filemap{$nick}{FH}, "+<tempout") || die "tempout: $!";
            print "open\n";
            $filemap{$nick}{RWIN} = [];
            $START = time;
        }

        print "*** RECV $srcip: @{[ length $data ]} ($seqno) $off...";
        # For speed, don't save
        my $fh = $filemap{$nick}{FH};
        seek $fh, $off, SEEK_SET;
        print $fh $data;
        ###print "wrote (@{[ length $data ]})...";
        print "write: $off-", $off + length($data), " (", length($data), ")\n";

        # Mark down each packet in our receive window
        #$rwin{$seqno}++;
        $filemap{$nick}{RWIN}[$seqno]++;
        if ($filemap{$nick}{RWIN}[$seqno] >= 2) {
            print "(DUPLICATE PACKET $seqno, IGNORED)\n";
        }

        # If last packet or last in RWIN, send NAKs
        print "TESTING: $len != ", ($mss-$SUMIHDRSZ), " or $seqno >= ",
              ($senders{$nick}{AT} + $rwinsz - 1), "...\n";
        if ($len != $mss - $SUMIHDRSZ || 
            $seqno >= $senders{$nick}{AT} + $rwinsz - 1) {
            my (@lost, $lost, $last);

            if ($seqno > $senders{$nick}{AT} + $rwinsz - 1) {
                print "WARNING: Got seqno greater than expected, sync?\n";
            } 

            $last = min($seqno, $senders{$nick}{AT} + $rwinsz - 1);

            print "Check ($senders{$nick}{AT} - $last): ";   @lost = ();
            # Check for missed packets (TODO: %missed for missed missed)
            # This should check AT to AT+RWIN packets
            # SENDER DOES NOT YET SUPPORT THIS
            for my $i ($senders{$nick}{AT}..$last) {
                push @lost, $i  if !$filemap{$nick}{RWIN}[$i];
                $lostpktcount++ if !$filemap{$nick}{RWIN}[$i];
            }                 @lost = ();
            foreach my $no (1..@{$filemap{$nick}{RWIN}} - 1) {
                push @lost, $no if $filemap{$nick}{RWIN}[$no] == 0;
            }
            $lost = join ",", @lost;
            print "Lost packets (@lost): ", 
                (scalar(@lost) ? scalar(@lost) : "NONE") . "\n";

            $senders{$nick}{AT} += $rwinsz;   # Keep the data flowing
            save_senders();

            # Shrink the window for each lost packet. This is done permanently
            # and cumulatively, which might not be a good idea if there are
            # short bursts of losses, rather than an overall loss
            # TODO: better windowing algorithm, average?
            $rwinsz -= @lost;

            # XXX: This resends packets, but
            # TODO: have a timeout to send this periodically if we never get
            # here, which is possible. Peridocially prime the pump..
            $conn->privmsg($nick, "n$rwinsz,$lost"); 
            print "Sent n$rwinsz, expecting $senders{$nick}{AT} ~ " .
                  $senders{$nick}{AT} + $rwinsz, "\n";
        }

        my @lost;
        foreach my $no (1..@{$filemap{$nick}{RWIN}} - 1) {
            push @lost, $no if $filemap{$nick}{RWIN}[$no] == 0;
        }

        # Less than full sized packet = last, so will tell file size
        if ($len != $mss - $SUMIHDRSZ) {
            $filemap{$nick}{SIZE} = tell($filemap{$nick}{FH});
            $done = 1 if !@lost;   # Got last packet, and nothing was lost
        }
        $done = 0 if @lost;
        if ($done) {
            my $DUR = time - $START;
            my $SIZE = $filemap{$nick}{SIZE};
            close($filemap{$nick}{FH});
            printf "Transfer complete in %.6f seconds\n", $DUR;
            print "Lost packet count: $lostpktcount\n";
            print "$SIZE at ", ($SIZE / $DUR / 1024), "KB/s\n";

            delete $filemap{$nick};
            delete $senders{$nick};
            $filemap{$nick}{RWIN} = [];

            #die "done\n";
       }
 
    }
}

sub min { return $_[0] < $_[1] ? $_[0] : $_[1] }

sub udp_serve
{
# based on http://cayfer.bilkent.edu.tr/~cayfer/ctp208/socket/
my ($cmd_port, $hostname, $handle) = @_;

my ($sockaddr, $name, $aliases, $proto, $type, $len, $myaddr);
my ($me);

# prepare socket for outbound data transfer
$sockaddr = "S n a4 x8";
($name,$aliases,$proto) = getprotobyname('udp');
($name,$aliases,$type,$len,$myaddr) = gethostbyname($hostname);

#$myaddr = pack"C4", 0, 0, 0, 0;
$myaddr = pack"C4", split /./, $localaddr;

my @my_ip = unpack("C4", $myaddr);
my $my_ip_addr  = join(".", @my_ip);
print "$my_ip_addr $hostname\n";

$me   = pack($sockaddr,&AF_INET, 0,     $myaddr);

socket(S, &AF_INET, &SOCK_DGRAM, $proto) || die $!;
setsockopt(S,&SOL_SOCKET,&SO_BROADCAST,1) || die $!;

bind(S, $me) || die $!;

# prepare socket for inbound command transfer (if any)
# Use IO::Select to check if there is any data to read in the socket
# IO::Select (see cpan.org) provides a library for NON-BLOCKING I/O

my $s = new IO::Select;
my $ip1 = IO::Socket::INET->new(LocalPort => $cmd_port, Proto=>'udp',
                                LocalAddr => $my_ip_addr)
	        or die "error creating UDP server for $my_ip_addr  $@\n";

$s -> add($ip1);  # sockets to check for pending data

my ($server, $remote_port, $remote_ipaddr, $cmd, $local_port, $local_ipaddr);
my @available_clients;
my $seq_no = 0;
my $actual_data;
my $stop_broadcast = 0;       # Broadcast on by default

while (1) {    # LOOP INDEFINITELY
  # Check if any command has arrived
  #sleep(1) if int rand(10) == 5;
  usleep(13);
  @available_clients = $s -> can_read(0);  
  foreach $server ( @available_clients) {
	  $server -> recv($cmd, 65535);

	  ($remote_port, $remote_ipaddr) = sockaddr_in($server -> peername);
	  ($local_port, $local_ipaddr)   = sockaddr_in($server -> sockname);
          $handle->($remote_ipaddr, $remote_port, $local_ipaddr, $local_port,
		$cmd);
  }
}
}

# aFOO\tbBAR\tcBAZ\tdQUX
sub parse_args
{
my ($args) = @_;
my (%args) = map { substr($_,0,1) => substr($_, 1) } split /\t/, $args;
return %args;
}

sub make_args
{
my (%args) = @_;
my (@args);
foreach my $key (keys %args)
{
    if (length($key) != 1) {
        die "trying to use |$key| instead of 1-character key!"
    }
    push @args, $key . $args{$key}
}
return join "\t", @args;
} 
