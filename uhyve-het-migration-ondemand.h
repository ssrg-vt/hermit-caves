#ifndef __UHYVE_ON_DEMAND__
#define __UHYVE_ON_DEMAND__

#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>

#include "uhyve-syscalls.h"

int client_socket;

typedef enum 
{
	HEAP, 
	BSS, 
	CLOSE
}section;

struct server_info
{
	int fd;
	int socket;
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


int on_demand_page_migration(uint64_t heap_size, uint64_t bss_size);
int send_page_request(section type, uint64_t address, char *buffer);
int connect_to_page_response_server();
#endif
