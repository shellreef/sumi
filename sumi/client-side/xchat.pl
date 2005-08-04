#!/usr/bin/perl
# Created:20040120
# By Jeff Connelly

# SUMI xchat client-side script
# 20040712: rewritten for xchat2, no patch required anymore
# Note, but doesn't use xchat2's new Xchat:: functions, still using old IRC::

# HOW TO USE THIS SCRIPT
# 1. Make sure you have xchat2 with Perl support (default in many builds)
# 2. Copy to ~/.xchat2 as sumi.pl (or whatever)
# 3. Modify SGW_PATH below to match your sumigetw.py location
# 4. Now xchat2 should say "SUMI xchat2 transport loading" at startup

# Use /sumi get sumi-00 #1 (for example) to download, after on a server.
# You can also manually invoke SUMI from the command like: sumigetw xchat ...
# And finally, you can also /load xchat.pl instead of saving it in ~/.xchat2

$SGW_PATH = "/home/jeff/p2p/sumi/sumigetw.py";  # Change to match your path
$XCHAT_FILE = "/tmp/xchat";  # Make sure this matches modxchat.py's

IRC::register("SUMI", "0.1", "", "");
IRC::add_command_handler("sumi", on_sumi);
IRC::add_command_handler("SIGUSR2", on_sigusr2);

IRC::print("SUMI xchat2 transport loading\n");

# /sumi X Y Z - this starts up sumiget
sub on_sumi
{
    my ($raw, $cmd, @args);

    $raw = $_[0];
    ($cmd, @args) = split /\s+/, $raw;
    if ($cmd eq "get") { sumi_get(@args); }

    return 1;
}

sub sumi_get
{
    my ($nick, $file) = @_;
    IRC::print("SUMI: You want $file from $nick");
    # TODO: find a way to background a process with list system
    system("$SGW_PATH xchat '$nick' '$file' &");
}

# New xchat2 feature (previously implemented as a patch for xchat1)
sub on_sigusr2
{
    open(CMD, "<$XCHAT_FILE") || die;
    local $/;
    my $cmd = <CMD>;
    IRC::command($cmd);

    # Comment this out if you rely on other /sigusr2 handlers
    return 1;
}
    
