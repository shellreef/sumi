// Created:20030729
// By Jeff Connelly

// SUMI server (sender)

#include <vector>
#include <string>
#include <map>
#include <fstream>

#include <stdio.h>      // sprintf

#include "../irc/irc.h"
#include "../endpoint/endpoint.h"

#include "md5.h"

#ifdef _WIN32
typedef unsigned long uint32_t;
#endif

std::string randip();

void on_connect(IRC* that, std::vector<std::string>& args);
void on_msg(IRC* that, std::vector<std::string>& args);
void on_ping(IRC* that, std::vector<std::string>& args);
void on_default(IRC* that, std::vector<std::string>& args);

void encode_base64(const char in[3], char out[4]);
void decode_base64(const char in[4], char out[2]);

void destroy(std::string nick);

// Old - seqno in srcport
//#define SUMIHDRSZ   4
// New - seqno in payload
#define SUMIHDRSZ     6

// Could use hash_map to speed this up a bit, but probably
// not worth the trouble. (I've had trouble w/ it).
//   These data structures hold information about the clients.
// Index is their unique name string
// Parallel vectors

std::map<std::string, int>          g_cli_auth;  // 0=no 1=half 2=done
std::map<std::string, int>          g_cli_mss;   // maximum segment size (UDP)
std::map<std::string, std::string>  g_cli_key;   // S->C authentication packet
std::map<std::string, std::string>  g_cli_prefix;// C->S authentication prefix
std::map<std::string, std::string>  g_cli_asrc;  // auth source IP address
std::map<std::string, std::string>  g_cli_addr;  // their IP:port
std::map<std::string, std::string>  g_cli_file;  // file they want
std::map<std::string, long>         g_cli_off;   // file offset(?)
std::map<std::string, long>         g_cli_seqno; // current sequence number
std::map<std::string, int>          g_cli_lat;   // latency
std::map<std::string, std::ifstream*>g_cli_fh;    // file handle

// Reject anything larger than this MSS on sight
const int global_mss = 5000;

// Controls which addresses will be used for file transfer.
// g_allow is the first part, g_mask is the second (1.2.3.4/24)
// Example: 1.2.0.0/16 would allow 1.2.0.0 - 1.2.255.255
// You only need to muck with this if your ISP has egress filtering,
// in which case it should be set to your subnet, in CIDR notation.

// Examples:
//     1.2.3.4/32  - use only IP 1.2.3.4
//     0/0         - use anything


uint32_t g_allow = 0;   // default: anything
uint32_t g_mask = 0;    // default: allow all

int main(int argc, char** argv)
{
    Endpoint::setup_raw(argv[0]);

    std::string allow, host;
    int cidr; uint32_t mask;

    if (argc < 2)
        allow = "0/0";
    else
        allow = argv[1];

    if (allow.find("/") == std::string::npos) 
    {
        g_allow = inet_addr(allow.c_str()); 
        cidr = 32;
    } else {
        g_allow = inet_addr(allow.substr(0, allow.find("/")).c_str());
        cidr = atoi(allow.substr(allow.find("/") + 1).c_str());
    }

    // Convert CIDR-notation to a subnet mask
    // 1-bits corresponding in the host address shall not change
    // 0-bits corresponding in the host address will be chosen at random
    g_mask = 0xffffffff;
    g_mask = htonl((0xffffffff >> (32 - cidr)) << (32 - cidr)); //XXX:ENDIAN!
    if (cidr == 0) g_mask = 0;    // Special case of all wildcarded

    std::cout << "Using: " << std::hex << g_allow << "/" 
              << g_mask << std::endl;

    //while(1) randip();

    IRC irc("ggrn.de.eu.deepirc.net");

    if (!irc) {
        std::cout << "failed to connect" << std::endl;
        return -1;
    }

    irc.set_handler("default", on_default);
    irc.set_handler("376", on_connect);
    irc.set_handler("PRIVMSG", on_msg);
    irc.set_handler("PING", on_ping);

    irc.login("sumiserv", "sumiserv", "sumiserv");

    return 0;
}

std::string randip()
{
    uint32_t ip;
    char* buf;

    ip = (rand() << 16) | (rand() & 0xffff);

    // Clear constant bits (network/subnet) from our random IP
    ip &= ~g_mask; 

    // Replace zero bits with constant bits from g_allow
    g_allow &= g_mask;     // Sanity
    ip |= g_allow;

    // Now we should have a random IP address within the allowable range

    in_addr a;
    a.s_addr = ip;
    buf = inet_ntoa(a);

    std::cout << "RANDIP: " << buf << std::endl;

    return std::string(buf);
}
 
void on_connect(IRC* that, std::vector<std::string>& args)
{
    that->send("JOIN", "#sumi", 0);
    //that->send("PRIVMSG", "#sumi", "sender ok", 0);
}

void datapkt(IRC* that, std::string nick, int seqno, std::string data)
{
    std::string prefix, pkt;
    int srcport;

    if (seqno == 0)
    {
        std::cout << "fatal error: data pkt trying to send auth pkt"
                  << std::endl;
        exit(23);
    }

    prefix = g_cli_prefix[nick];

    if (prefix.length() != 3)  // important its not empty
    {
        that->send("PRIVMSG", nick.c_str(), "error: prefix is not 3", 0);
        std::cout << "datapkt: prefix != 3, its "
                  << g_cli_prefix[nick].length() << " instead" << std::endl;
        exit(-4);    // for now, its fatal (should stop talking to client)
    }
    
    if (seqno > 16777216)      // 8-10GB is the limit
    {
        that->send("PRIVMSG", nick.c_str(), "error: file too large", 0);
        return;  // todo: destroy user data structures
    } 

    // The source port is upper 16 bits of seqno
    srcport = (seqno & 0xffff00) >> 8;

    if (srcport == 0)
        srcport = 0xffff;     // exception

    pkt = "PREseq" + std::string(data.data(), data.length());
    pkt[0] = prefix[0]; 
    pkt[1] = prefix[1];
    pkt[2] = prefix[2];
    pkt[3] = seqno & 0xff;
    //COMPAT NOTE: This is new
    pkt[4] = (seqno & 0xff00) >> 8;
    pkt[5] = (seqno & 0xff0000) >> 16;

    if (pkt.length() > g_cli_mss[nick]) 
    {
        std::cout << "fatal: trying to send packet larger than MSS" 
                  << "try=" << pkt.length() << " (" << data.length() << ")" 
                  << " " << nick << "'s mss=" << g_cli_mss[nick]
                  << std::endl;
        exit(2);
    }

    std::ostringstream os;
    os << srcport;

    Endpoint udp(RAW_UDP, EndpointAddrlist(g_cli_addr[nick]),
                          EndpointAddrlist(randip() + ":" + os.str()));

    if (!udp)
    {
        std::cout << "couldn't create UDP" << std::endl;
        exit(-42);
    } 

#ifndef _WIN32
    usleep(g_cli_lat[nick]);        // microsecond
#else
    Sleep(g_cli_lat[nick] / 1000.); // millisecond
#endif
    udp.Write(pkt);
    std::cout << "." << std::flush;
}

// Handles transfer messages
void transfer_control(IRC* that, std::string nick, std::string msg)
{
    std::string filename, prefix;
    int mss;

    filename = g_cli_file[nick];
    prefix   = g_cli_prefix[nick];
    mss      = g_cli_mss[nick];

    if (msg.find("n") == 0)         // n<win>,<resend-1>,<resend-2>
    {
        std::vector<long> resends;
        int winsz;

        // Parse selective resends
        msg = msg.substr(1);
        msg += ",";

        while(1)                 // parse comma-separated fields
        {
            std::string arg;
            int n = msg.find(",");
            if (n == std::string::npos)
                break;
            arg = msg.substr(0, n);
   
            resends.push_back(atoi(arg.c_str()));
            msg = msg.substr(n + 1);
        }
        winsz = resends[0];
        resends.erase(resends.begin());

        std::cout << "WIN=" << winsz << "** resends: " << std::endl;

        // Lower window size to not include resent packets, if any
        winsz -= resends.size();

        // If there are any resends, send them first
        for (int i = 0; i < resends.size(); i++)     // TODO: use iterators
        {
            if (i == 0)
                continue; 
            std::cout << "Resending " << i << std::endl; 
            //g_cli_fh[nick]->seekg(, std::ios_base::beg);
            datapkt(that, nick, i, "data here");
            std::cout << "Resending is being worked on ok?" << std::endl;
            exit(42);
        }
 
        if (!g_cli_seqno[nick])      // first, set it up
        {
            g_cli_seqno[nick] = 1;
            std::ifstream* is = new std::ifstream("1mb", std::ios::in | std::ios::binary);
            if (!is) 
            {
                // file should always exist if advertised
                std::cout << "fatal error: couldn't open data.txt" << std::endl;
                exit(3);
            }
            g_cli_fh[nick] = is;
            std::cout << "Starting transfer to " << nick << "..." << std::endl;
        }

        if (g_cli_seqno[nick] == -1)  // finished, no more non-resends
        {
            // This may occur multiple times, if packets are lost multiple
            // times. There's no way to know. Just update it if we get more.
            std::cout << "Finished transfer to " << nick << "." << std::endl;
            destroy(nick);
            return;
        }

        // Read in blocks of (mss-SUMIHDRSZ)
        // XXX: After rexmits implemented, should do a seekg() here too
        for (int j = 0; j <= winsz; j++)
        {
#ifndef _WIN32
            char blk[mss - SUMIHDRSZ];
#else
            char blk[8192];
#endif

            g_cli_fh[nick]->read(blk, mss - SUMIHDRSZ);

            // Note: when char*->string, do not use =, it ignores nulls
            // gcount() gets number of chars we just read
            std::string str(blk, g_cli_fh[nick]->gcount());

            datapkt(that, nick, g_cli_seqno[nick], str);
            std::cout << g_cli_seqno[nick] << " " << std::flush;

            g_cli_seqno[nick]++;
            if (g_cli_fh[nick]->eof())
            {
                if (g_cli_fh[nick]->gcount() == mss - SUMIHDRSZ)
                {
                    // If the last block read was not complete, then the
                    // recipient knows its end of file. In the rare case
                    // that ALL blocks are full sized, even the EOF, send
                    // a zero-byte datagram to tell the client its EOF
                    datapkt(that, nick, g_cli_seqno[nick], "");
                }

                // Client may have missed some blocks so leave it open for
                // resends but don't send anymore
                g_cli_seqno[nick] = -1;
                break;
            }
        }
    } 
}

void destroy(std::string nick)
{
    g_cli_auth[nick] = 0;
    g_cli_mss[nick] = 0;
    g_cli_key[nick] = "";
    g_cli_prefix[nick] = "";
    g_cli_asrc[nick] = "";
    g_cli_addr[nick] = "";
    g_cli_file[nick] = "";
    g_cli_off[nick] = 0;
    g_cli_lat[nick] = 0;
}

void on_msg(IRC* that, std::vector<std::string>& args)
{
    std::string from, to, msg, nick;

    from = args[0];
    to   = args[2];
    msg  = args[3];

    nick = from.substr(0, from.find("!"));
    std::cout << "<" << nick << ">" << msg << std::endl;

    if (g_cli_auth[nick] == 2)   // use shorter protocol
    {
        transfer_control(that, nick, msg);
    }

    // I admit, I don't know why this needs to be here. Don't remove it,
    // otherwise this hash will lose its values! (This was only needed
    // when using hash_map with const char*.)
    //g_clients["sumiget"];

    if (msg.find("sumi send ") == 0) {
         std::vector<std::string> fields;
         std::string file, offset, ip, port, b64prefix, latency, key;
         char prefix[4];
         int mss;
 
         std::cout << nick << " is sumi sending" << std::endl;

         // Clear out data structures, start fresh
         destroy(nick);

         msg = msg.substr(10) + "\t";

         while(1)           // parse tab-separated fields
         {
             std::string arg; 
             int n = msg.find("\t");
             if (n == std::string::npos)
                 break;
             arg = msg.substr(0, n);

             fields.push_back(arg);
             msg = msg.substr(n + 1);
         }
         if (fields.size() < 7) {
             that->send("PRIVMSG", nick.c_str(), "error: fields <7", 0);
             return;
         }

         file      = fields[0];
         offset    = fields[1];
         ip        = fields[2];
         port      = fields[3];
         mss       = atoi(fields[4].c_str());
         b64prefix = fields[5];
         latency   = fields[6];

         if (mss < 256) {
             that->send("PRIVMSG", nick.c_str(), "error: MSS too small <256",0);
             return;
         }

         if (b64prefix.length() != 4) {
             that->send("PRIVMSG", nick.c_str(), "error: prefix != 4", 0);
             return;
         }

         // Prefix is base64-encoded for IRC transport
         decode_base64(b64prefix.c_str(), prefix); 
         prefix[3] = 0;

         // TODO: save this
         std::cout << "nick=" << nick << " FILE=" << file << " OFFSET=" 
                   << offset << " IP=" << ip << ":" << port << " MSS=" 
                   << mss << " PREFIX=" << b64prefix << std::endl;

         g_cli_mss[nick]    = mss;
         g_cli_file[nick]   = file;
         g_cli_off[nick]    = atoi(offset.c_str());
         g_cli_addr[nick]   = "[" + ip + "]:" + port;
         g_cli_prefix[nick] = prefix;
         std::cout << "For " << nick << ", using prefix of len=" 
                   << g_cli_prefix[nick].length() << std::endl;
         g_cli_lat[nick]    = atoi(latency.c_str());

         printf("PREFIX0=%.2x\n", prefix[0]);
         printf("PREFIX1=%.2x\n", prefix[1]);
         printf("PREFIX2=%.2x\n", prefix[2]);

         //std::cout << "g_clients[" << nick << "] = " << g_clients[nick] << std::endl;

         if (mss > global_mss) {
                that->send("PRIVMSG", nick.c_str(), "error: mss too large", 0);
                return;
         }

         prefix[3] = 0;
         key = prefix;
         key += "X"; key[3] = 0;       // seqno placeholder (append NUL)
         key += "X"; key[4] = 0;       //COMPAT NOTE: these two nulls are new
         key += "X"; key[5] = 0;
         if (key.length() != SUMIHDRSZ) {
             that->send("PRIVMSG", nick.c_str(), "error: key + nul != SUMIHDRSZ", 0);
             return;
         }
         for (int i = 1; i <= mss - SUMIHDRSZ; i++)
             key += "X"; 

         if (key.length() != mss) {
             std::cout << "bad key generation: " << key.length() << " != " 
                       << mss << std::endl;
             return;
         }

         Endpoint udp(RAW_UDP | CLIENT, "[" + ip + "]:" + port,
                      (g_cli_asrc[nick] = randip()) + ":0");
         //g_cli_asrc[nick] = ip;
         if (!udp) {
             that->send("PRIVMSG", nick.c_str(), "error: udp error", 0);
             return;
         }

         g_cli_key[nick] = key;

         udp.Write(key);

         std::cout << "Packet SENT" << std::endl;

         g_cli_auth[nick] = 1;        // first step complete

    } else if (msg.find("sumi auth ") == 0) {       // sent in response to auth pkt
         std::string srcip, hash;
         int n, mss;

         if (g_cli_auth[nick] != 1) {
             that->send("PRIVMSG", nick.c_str(), "error: step 1 not complete", 0);
             return;
         }

         msg = msg.substr(10);
         n = msg.find("\t");
         if (n == std::string::npos) {
             that->send("PRIVMSG", nick.c_str(), "error: malformed src", 0);
             return;
         }
         mss = atoi(msg.substr(0, n).c_str());
         msg = msg.substr(n + 1);

         n = msg.find("\t");
         if (n == std::string::npos) {
            that->send("PRIVMSG", nick.c_str(), "error: malformed hash", 0);
            return;
         }
         srcip = msg.substr(0, n);
         msg = msg.substr(n + 1);
         hash = msg;
         if (hash.find("\r") != std::string::npos) {
             hash = hash.substr(0, hash.find("\r"));
         }

         std::cout << "auth: mss=|" << mss << "|, srcip=|" << srcip << "|, hash=|" << hash << "|" 
                   << std::endl;

         // Verify MSS
         if (mss < g_cli_mss[nick]) {
             if (mss < 256) {
                 that->send("PRIVMSG", nick.c_str(), "error: MSS <256", 0);
                 return;
             }
             std::cout << "Downgrading MSS " << g_cli_mss[nick] << " -> " << mss << std::endl;
             g_cli_mss[nick] = mss;
         } else if (mss > g_cli_mss[nick]) { 
             std::cout << "MSS too high! " << g_cli_mss[nick] << " -> " << mss << std::endl;
             that->send("PRIVMSG", nick.c_str(), "error: MSS >", 0);
             return;
         }

         // Verify src ip
         std::cout << "Verifying spoofing capabilities..." << std::endl;
         if (g_cli_asrc[nick] != srcip) {
             std::cout << "*** Warning: Possible spoof failure! We sent from " << 
                           g_cli_asrc[nick] << std::endl
                       << "but client said we sent from " << srcip << std::endl;
             std::cout << "If this happens often, either its a problem with your ISP, " << std::endl
                       << "or the work of mischevious clients. Dropping connection." << std::endl;
             // TODO: Make the errors less specific, or better yet, optional.
             // If this drastic error occurs and the client isn't lying, then
             // our IP has been revealed. Don't let them know nothing!
             that->send("PRIVMSG", nick.c_str(), "error: srcip", 0);
             return;
         }

         // Verify hash
         std::cout << "Verifying authenticity of client..." << std::endl;

         // The hash has to be calculated AFTER the auth string is received
         // so we now how much of it to hash (the MSS)
         MD5_CTX context;
         unsigned char digest[16];
         std::string strdigest, key;

         key = g_cli_key[nick];

         if (mss > key.length()) {    // trying to buffer overflow, eh..
             std::cout << nick << "'s MSS of " << mss << " is > " 
                       << key.length() << "!" << std::endl;
             return;
         }

         MD5Init(&context);
         MD5Update(&context, (unsigned char*)key.c_str(), mss);
         MD5Final(digest, &context);         

         char tmp[3] = { 0, 0, 0 };
         for (int i = 0; i < 16; i++)
         {
             sprintf(tmp, "%.2x", digest[i]);
             strdigest += tmp;
         }

         if (hash != strdigest) {
             std::cout << hash << " != " << strdigest << std::endl;
             that->send("PRIVMSG", nick.c_str(), "error: hash", 0);
             return;
         }

         std::cout << nick << " is verified!" << std::endl;
         g_cli_auth[nick] = 2;     // fully authenticated, let the transfer begin

         // Inconsistancy: server doesn't usually talk on IRC,
         // but it does here. The client needs to know when to start.
         that->send("PRIVMSG", nick.c_str(), "sumi start tempout\t0\t16000",0 );
    }
    //std::cout << "g_clients['sumiget'] = " << g_clients["sumiget"] << std::endl;
}

void on_ping(IRC* that, std::vector<std::string>& args)
{
    std::cout << "." << std::flush;
    that->send("PONG", args[2].c_str(), 0);
}

void on_default(IRC* that, std::vector<std::string>& args)
{
    for (int i = 0; i < args.size(); i++)
        std::cout << args[i] << " ";
    std::cout << std::endl;
}


static char to_base64_set[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";
static char from_base64_set[] = {
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,    // 00-0f
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,    // 10-1f   
    0, 0,62, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,63,    // 20-2f   
   52,53,54,55,56,57,58,59,60,61, 0, 0, 0, 0, 0, 0,    // 30-3f
    0, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,    // 40-4f
   15,16,17,18,19,20,21,22,23,24,25, 0, 0, 0, 0, 0,    // 50-5f
    0,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,    // 60-6f
   41,42,43,44,45,46,47,48,49,50,51, 0, 0, 0, 0, 0,    // 70-7f
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,    // 80-8f
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,    // 90-9f
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,    // a0-af
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,    // b0-bf
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,    // c0-cf
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,    // d0-df
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,    // e0-ef
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,    // f0-ff
};

void encode_base64(const char in[3], char out[4])
{
   out[0] = to_base64_set[in[0] >> 2];
   out[1] = to_base64_set[((in[0] & 3) << 4) | ((in[1] & 0xf0) >> 4)];
   out[2] = to_base64_set[(in[1] & 0xf) << 2 | ((in[2] & 0xc0) >> 6)];
   out[3] = to_base64_set[in[2] & 0x3f];
}

void decode_base64(const char input[4], char out[3])
{
   char in[4];
   in[0] = from_base64_set[(int)input[0]];
   in[1] = from_base64_set[(int)input[1]];
   in[2] = from_base64_set[(int)input[2]];
   in[3] = from_base64_set[(int)input[3]];

   out[0] = (in[0] << 2) | (in[1] >> 4);
   out[1] = (in[1] << 4) | (in[2] >> 2);
   out[2] = (in[2] << 6) | in[3];
}

