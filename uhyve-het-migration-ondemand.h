#ifndef __UHYVE_ON_DEMAND__
#define __UHYVE_ON_DEMAND__

#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>

#include "uhyve-syscalls.h"

int client_socket;
int ondemand_migration_port;

typedef enum {
	SECTION_HEAP = 0,
	SECTION_BSS,
	SECTION_CLOSE
} section_t;

struct server_info {
	int fd;
	int socket;
};

struct packet {
	section_t type;
	uint64_t address;
};

int on_demand_page_migration(uint64_t heap_size, uint64_t bss_size);
int send_page_request(section_t type, uint64_t address, char *buffer);
int connect_to_page_response_server();
#endif
