/* Created:20040715
 * (C) Jeff Connelly 2004
 * (C) Dan Weber 2004
 * $Id$
 * $LastModified$
 * Raw socket proxy
 
 * The idea behind this program is to help out users who want to
 * anonymously serve with sumiserv but can't spoof for one reason
 * or another. rawproxd can be run on the NAT box, and all clients
 * behind it will be able to connect and send anonymously.
 */
#include <unistd.h>
#include <errno.h>
#include <iostream>
#include <string>
#include <cstdio>
#include <cstring>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <cppsocket/socket.h>
#include <cppsocket/exception.h>

#define PORT 7010


using namespace std;


inline void check_socket_fail(int errnum) {
   switch(errnum) {
    case EBADF:  
      cout << "sockfd is not a valid descriptor." << endl;
      break;
      
    case EINVAL: 
      cout << "The socket is already bound to an address.  This may change in the future: see linux/unix/sock.c for details." << endl;
      break;
      
    case EACCES: 
      cout << "The address is protected, and the user is not the super-user." << endl;
      break;
      
    case ENOTSOCK:
      cout << "Argument is a descriptor for a file, not a socket." << endl;
      break;
    case EADDRNOTAVAIL:
      cout << "Address Not Available" << endl;
      break;
   }
}

int main()
{
   try 
     {
	// Declarations
	int rs;
	// Create an instance of the Weber Vector
	// WeberVector<char> buf;
	char buf[1500];
	CPPSocket::Socket server;
	CPPSocket::Address serverAddress(CPPSocket::Address::ANY_IP, PORT, true);
	CPPSocket::Socket connection;
	CPPSocket::Address clientAddress;
	size_t MTU = 1500;
	
	// Check to see if root, then setuid
	if (getuid() == 0)
	  setuid(getuid());
	else 
	  {
	     cerr << "Not root" << endl;
	     return EXIT_FAILURE;
	  }
	
	// Creating raw socket
	rs = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
	if (rs < 0) {
	   cout << "failed to create raw socket" << endl;
	   check_socket_fail((int)errno);
	   exit(-1);
	}
   
	// Set server to a TCP Connection
	server.open(CPPSocket::Socket::TCP);
	
	// Allow reusage of an address
	server.setsockopt(CPPSocket::SocketOption::ReuseAddr(1));
	
	// Bind the server
	server.bind(serverAddress);
	
	// Set server queue length
	server.listen(5);
	
	// Wait for TCP connection
	cout << "Waiting for Connection" << endl;
	connection = server.accept(clientAddress); // Note, this will block code until a connection is made
	clientAddress.lookup();
	
	while(1)
	  {
	     cout << "Receiving " << MTU << " bytes...\n";
	     /*      if (recv(cs, &buf, MTU, MSG_WAITALL) == 0)
	      break; */
	     if (connection.recv(buf,MTU,0) == 0)
	       break;
	     cout << "Sending to raw socket...\n";
	     send(rs, &buf, MTU, 0);
	  }
	
	// Destructors
	close(rs);
	connection.close();
	server.close();
     }
   catch (CPPSocket::Exception &e) 
     {
	cerr << e.getMessage() << endl;
	return EXIT_FAILURE;
     }
   return EXIT_SUCCESS;
}
