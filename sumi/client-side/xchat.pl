#!/usr/bin/perl
# Created:20040120
# By Jeff Connelly

# SUMI xchat client-side script
# 20040712: rewritten for xchat2, no patch required anymore

$XCHAT_FILE = "/tmp/xchat";  # Make sure this matches modxchat.py's

IRC::register("SUMI", "0.1", "", "");
IRC::add_command_handler("sumi", on_sumi);
IRC::add_command_handler("SIGUSR2", on_sigusr2);

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
    system("/home/jeff/p2p/sumi/sumigetw.py xchat '$nick' '$file' &");
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
    
