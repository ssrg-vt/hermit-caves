#ifndef __UHYVE_ON_DEMAND__
#define __UHYVE_ON_DEMAND__

#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>

#include "uhyve-syscalls.h"

typedef enum 
{
	HEAP, 
	BSS, 
	CLOSE
}section;

struct server_info
{
	int fd;
	int addrlen;
	struct sockaddr_in address;
};

struct packet
{
	section type;
	uint64_t address;
};

struct packet_socket
{
	int socket;
	struct packet *recv_packet;
};


int on_demand_page_migration();
int send_page_request(section type, uint64_t address, char *buffer);
#endif
