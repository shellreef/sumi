// Created;20030809
// By Jeff Connelly

// UNIX program to create a raw socket

#include <iostream>
#include <string>

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <unistd.h>

#include <stdio.h>

int main(int argc, char** argv)
{
    int fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    std::string program;
    char* buf;

    if (fd < 0)
    {
        std::cout << argv[0] << ": couldn't create raw socket" << std::endl;
        exit(1);
    }

    buf = new char[20];
    memset(buf, 0, 20);
    sprintf(buf, "RAWSOCKFD=%d", fd);

    putenv(buf);

    std::cout << argv[0] << ": using socket " << fd << "..." << std::endl;

    setuid(getuid());

    std::cout << argv[0] << ": running as user " << getuid() << std::endl;

    for (int i = 1; i < argc; i++)
        program += std::string(argv[i]) + " ";

    return system(program.c_str());
}
