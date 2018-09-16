#ifndef __UHYVE_ON_DEMAND__
#define __UHYVE_ON_DEMAND__

#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>

#include "uhyve-syscalls.h"

int client_socket;
int ondemand_migration_port;

typedef enum {
	AREA_HEAP = 0,
	AREA_BSS,
	AREA_DATA,
	AREA_CLOSE // FIXME is CLOSE actually used somewhere?
} area_t;

struct server_info {
	int fd;
	int socket;
};

struct packet {
	area_t type;
	uint64_t address;
	uint8_t npages;
	uint32_t page_size;
};

int on_demand_page_migration(uint64_t heap_size, uint64_t bss_size, uint64_t data_size);
int send_page_request(area_t type, uint64_t address, char *buffer,
		uint8_t npages, uint32_t page_size);
int connect_to_page_response_server();
#endif
