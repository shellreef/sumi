/* Created:20040715
 * By Jeff Connelly
 
 * Raw socket proxy
 
 * The idea behind this program is to help out users who want to
 * anonymously serve with sumiserv but can't spoof for one reason
 * or another. rawproxd can be run on the NAT box, and all clients
 * behind it will be able to connect and send anonymously.
 */

#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

#define PORT 7009
#define MTU 1500

int main()
{
    int ss, sin_size, cs, rs;
    struct sockaddr_in my_addr;
    struct sockaddr_in their_addr; 
    char buf[1500];

    rs = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (rs < 0) {
        printf("failed to create raw socket\n");
        exit(-1);
    }
    setuid(getuid());
 
    ss = socket(AF_INET, SOCK_STREAM, 0);
    if (ss < 0) {
        printf("failed to create server socket\n");
        exit(-2);
    }

    my_addr.sin_family = AF_INET;
    my_addr.sin_port = htons(PORT);
    memset(&(my_addr.sin_zero), 0, 8);
    /* this fails, I don't know why */
    if (bind(ss, (struct sockaddr*)&my_addr, sizeof(struct sockaddr)) < 0) {
        printf("failed to bind\n");
    }
    
    if (listen(ss, 5) < 0) {
        printf("failed to listen\n");
        exit(-3);
    }

    sin_size = sizeof(struct sockaddr_in);

    printf("Waiting for connection...\n"); 
    cs = accept(ss, (struct sockaddr*)&their_addr, &sin_size);
    if (cs < 0) {
        printf("failed to accept\n");
        exit(-4);
    }

    while(1)
    {
        printf("Receiving %d bytes...\n", MTU);
        if (recv(cs, buf, MTU, MSG_WAITALL) == 0)
            break;
        printf("Sending to raw socket...\n");
        send(rs, buf, MTU, 0);
    }
    close(rs);
}

