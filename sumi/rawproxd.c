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
 */
#include <errno.h>
#include <stdio.h>

#ifdef _WIN32
#include <winsock2.h>
#else
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#define closesocket    close
#endif

#define PORT	7011
#define MTU	1500
#define BACKLOG    1

int main()
{
	char buf[MTU];
	int server, client, rs;
	struct sockaddr_in server_addr;
	struct sockaddr_in client_addr;
	socklen_t addr_len;
	int on = -1;

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

 
	server = socket(AF_INET, SOCK_STREAM, 0);
	if (server < 0)
	{
		perror("TCP socket creation failed");
		exit(-3);
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

        /*
	if (setsockopt(server, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on) == -1))
	{
		perror("setsockopt failed");
		exit(-4);
	} */

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

	printf("Waiting for connection...\n");
	client = accept(server, (struct sockaddr*)&client_addr, &addr_len);
	if (client < 0)
	{
		perror("accept failed");
		exit(-7);
	}

	while(1)
	{
		struct sockaddr_in dest_addr;
		char* msg;
		int wrote, read;

		printf("Reading %d bytes...\n", MTU);
		read = recv(client, buf, MTU, MSG_WAITALL);
		if (read == -1)
		{
			perror("recv failed");
			break;
		} else if (read == 0) {            /* EOF */
			break;
		} else if (read != MTU) {
			printf("partial read: %d != %d\n", read, MTU);
			break;                     /* Usually catastrophic */
		}

		memset(&dest_addr, 0, sizeof(struct sockaddr));
		dest_addr.sin_family = AF_INET;
		dest_addr.sin_port = htons(PORT);

		/* Get destination address from packet. */	
		/* Already in network order, so don't convert endian. */	
		memcpy(&dest_addr.sin_addr.s_addr, &buf[17], 4);

		printf("dest addr = %s\n", inet_ntoa(dest_addr.sin_addr));

		printf("Sending to raw socket...\n");
		/* Strange how IP_HDRINCL raw sockets require sendto(), 
                 * therefore requiring the dest addr to be specified twice. */
		wrote = sendto(rs, buf, MTU, 0, 
		               (struct sockaddr*)&dest_addr, addr_len);
		if (wrote == -1)
		{
			/* If fails with invalid argument, check if ip_len
			 * is in host order (on FreeBSD), or network endian
			 * order, depending on the operating system. */
			/* XXX: Fails with invalid argument with either endian?*/
			perror("sendto raw failed");
			break;
                } else if (wrote != MTU) {
			printf("partial write: %d < %d\n", wrote, MTU);
			break;
		}
	}

	closesocket(rs);
	closesocket(client);
	closesocket(server);

	return 0;
}
