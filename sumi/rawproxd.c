/* Created:20040715
 * Copyright (C) Jeff Connelly 2004
 * Copyright (C) Dan Weber 2004
 * $Id$
 * $LastModified$
 * Raw socket proxy
 
 * The idea behind this program is to help out users who want to
 * anonymously serve with sumiserv but can't spoof for one reason
 * or another. rawproxd can be run on the NAT box, and all clients
 * behind it will be able to connect and send anonymously.
 *
 * rawproxd is written in C instead of C++ so it can be compatible with
 * uclibc on the Linksys WRT54G/WRT54GS mipsel routers, which lack libstdc++.
 *
 * This file uses tabs - please don't collapse them to spaces when editing.
 */

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

#include "hash/md5a.h"

#ifdef _WIN32
#include <winsock2.h>
#else
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#define closesocket    close
#endif

#define PORT	       7010
#define MTU	       1500
#define BACKLOG           1
#define CHALLENGE_LEN    32

#ifndef MSG_WAITALL
/* Dan Weber has let me compile rawproxd.c on his box, which works. Doesn't
 * work on my FreeBSD system. 
 */
#error Your cross-compilation toolchain doesn't seem to be setup correctly (missing MSG_WAITALL). Make sure you are using mipsel-linux-gcc. The /usr/ports/devel/mipsel-linux-gcc port on FreeBSD doesn't seem to work correctly, please try the Debian package instead.
#endif

int handle_client(int rs, int client, struct sockaddr_in client_addr, 
                  int addr_len, char* pw);

int main(int argc, char** argv)
{
	int server, client, rs;
	struct sockaddr_in server_addr;
	struct sockaddr_in client_addr;
	socklen_t addr_len;
	int on = 1;
	char* pw;


#ifdef _WIN32
	WSADATA wsaData;
	if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
		printf("couldn't load WinSock 2.0");
		exit(-8);
	}
#endif

	/* First things first: create the raw socket. */
	rs = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
	if (rs < 0) {
		perror("raw socket creation failed");
		exit(-1);
	}
	
	/* Drop priviledges as they are no longer needed. */
	if (setuid(getuid()) != 0)
	{
		perror("setuid failed");
		exit(-2);
	}

	/* If password on command line, use it. */
	if (argc >= 2) {
		pw = argv[1];
	} else {
		pw = "";
		printf("WARNING: Not using a password. Anyone can connect.\n");
		printf("For better security, run %s <passoword\n", argv[0]);
	}


	srand(time(0));
 
	server = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (server < 0)
	{
		perror("TCP socket creation failed");
		exit(-3);
	}

	if (setsockopt(server, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) == -1)
	{
		perror("setsockopt SO_REUSEADDR failed");
		exit(-4);
	}

	memset(&(server_addr), 0, sizeof(struct sockaddr));
	server_addr.sin_family = AF_INET;
	server_addr.sin_port = htons(PORT);
	server_addr.sin_addr.s_addr = INADDR_ANY;

	if (bind(server, (struct sockaddr*)&server_addr, 
	    sizeof(struct sockaddr)) != 0) 
	{
		perror("bind failed");
		exit(-5);
	}

	/* Include the IP header, do this after bind(). */
	if (setsockopt(rs, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) != 0)
	{
		perror("setsockopt IP_HDRINCL failed");
		exit(-9);
	}
	
	if (listen(server, BACKLOG) != 0)
	{
		perror("listen failed");
		exit(-6);
	}

	while(1)
	{
		printf("Waiting for connection...\n");
		client = accept(server, (struct sockaddr*)&client_addr, 
		                &addr_len);
		if (handle_client(rs, client, client_addr, addr_len, pw) < 0)
			break;
		closesocket(client);
	}

	printf("Shutting down...\n");
	closesocket(client);
	closesocket(rs);
	closesocket(server);
}

int handle_client(int rs, int client, struct sockaddr_in client_addr, 
                  int addr_len, char* pw)
{
	md5_state_t state;
	FILE* urandom;
	char buf[MTU];
	char challenge[CHALLENGE_LEN];
	char response[16];
	md5_byte_t digest[16];
	int i;

	if (client < 0)
	{
		perror("accept failed");
		exit(-7);
	}

	printf("Connected\n");

	/* Challenge-response password-based login. */
	urandom = fopen("/dev/urandom", "rb");      /* WRT54GS has this. */
	if (!urandom)
	{
		/* Not available (on Windows, for example), so use rand(). */
		printf("WARNING: Using bad random number generator.\n");
		for (i = 0; i < CHALLENGE_LEN; i++)
		{
			challenge[i] = rand();	
			printf("%02x ", challenge[i]);
		}
		printf("\n");
	} else {
		if (fread(challenge, 1, CHALLENGE_LEN, urandom) != 
		    CHALLENGE_LEN) 
		{
			perror("couldn't read enough bytes from /dev/urandom");
			exit(-9);
		}
	}

	if (send(client, challenge, CHALLENGE_LEN, MSG_WAITALL) 
	    != CHALLENGE_LEN)
	{
		perror("couldn't send challenge to client");
		return;
	}

	/* 16-byte (=128-bit) MD5 hash is the response. */
	if (recv(client, response, 16, MSG_WAITALL) != 16)
	{
		perror("couldn't read challenge response");
		return;
	}

	md5_init(&state);
	md5_append(&state, (const md5_byte_t*)challenge, CHALLENGE_LEN);
	md5_append(&state, (const md5_byte_t*)pw, strlen(pw));
	md5_finish(&state, digest);
	/*for (i = 0; i < 16; i++)
		printf("%02x", digest[i]);
	printf("\n");*/

	/* Check password. If no password, let anything in. */
	if (pw[0] && memcmp(digest, response, 16) != 0)
	{
		printf("Denied %s\n", inet_ntoa(client_addr.sin_addr));
		return;
	}	
	printf("Accepted %s\n", inet_ntoa(client_addr.sin_addr));
	send(client, "\xff", 1, MSG_WAITALL);

	while(1)
	{
		struct sockaddr_in dest_addr;
		char* msg;
		int wrote, read;
		unsigned short magic;
		unsigned short len;

		/* Simple header--"RP" magic and packet length. */
		recv(client, &magic, 2, MSG_WAITALL);
		magic = ntohs(magic);
		if (magic != 0x5250)
		{
			printf("invalid magic within stream: %.4x (not 0x5250)\n", magic);
			return;
		}

		recv(client, &len, 2, MSG_WAITALL);
		len = ntohs(len);
		printf("Length: %d\n", len);
		if (len > MTU)
		{
			printf("packet too big: %d > %d\n", len, MTU);
			exit(-4);
		}
		printf("Reading %d bytes...\n", len);
		read = recv(client, buf, len, MSG_WAITALL);
		if (read == -1)
		{
			perror("recv failed");
			break;
		} else if (read == 0) {            /* EOF */
			break;
		} else if (read != len) {
			printf("partial read: %d != %d\n", read, MTU);
			break;                     /* Usually catastrophic */
		}

		memset(&dest_addr, 0, sizeof(struct sockaddr));
		dest_addr.sin_family = AF_INET;
		dest_addr.sin_port = htons(PORT);

		/* Get destination address from packet. */	
		/* Already in network order, so don't convert endian. */	
		memcpy(&dest_addr.sin_addr.s_addr, (char*)buf + 16, 4);

		printf("dest addr = %s\n", inet_ntoa(dest_addr.sin_addr));

		addr_len = sizeof(struct sockaddr_in);

		/* Strange how IP_HDRINCL raw sockets require sendto(), 
                 * therefore requiring the dest addr to be specified twice. */
		wrote = sendto(rs, buf, MTU, 0, 
		               (struct sockaddr*)&dest_addr, addr_len);
		if (wrote == -1)
		{
			/* Note: if invalid argument, make sure right endian. */
			perror("sendto raw failed");
			break;
                } else if (wrote != MTU) {
			printf("partial write: %d < %d\n", wrote, MTU);
			break;
		}
	}

	closesocket(client);

	return 0;
}
