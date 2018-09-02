#define _DEFAULT_SOURCE

#include <unistd.h>
#include <stdio.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <string.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <ifaddrs.h>
#include <math.h>
#include <fcntl.h>
#include <signal.h>
#include <err.h>
#include <sys/mman.h>
#include <sys/time.h>
#include <linux/kvm.h>

#include "uhyve.h"
#include "uhyve-het-migration-ondemand.h"

#define CHKPT_MDATA_FILE	"mdata.bin"
#define CHKPT_STACK_FILE	"stack.bin"
#define CHKPT_BSS_FILE		"bss.bin"
#define CHKPT_DATA_FILE		"data.bin"
#define CHKPT_HEAP_FILE		"heap.bin"
#define CHKPT_TLS_FILE		"tls.bin"
#define CHKPT_FDS_FILE		"fds.bin"

#define PAGE_SIZE 	4096
#define NI_MAXHOST 	1025

extern int client_socket;
extern __thread int vcpufd;
extern uint64_t aarch64_virt_to_phys(uint64_t vaddr);

char run_server = 1;

struct server_info* setup_page_response_server() {
	int opt = 1;
	int addrlen;
	struct sockaddr_in address;

	struct server_info* server =
		(struct server_info*)malloc(sizeof(struct server_info));
	if(!server)
		err(EXIT_FAILURE, "Malloc Failed");

	addrlen = sizeof(address);

	// Creating socket file descriptor
	if ((server->fd = socket(AF_INET, SOCK_STREAM, 0)) == 0)
		err(EXIT_FAILURE, "Socket Failed");

	// Forcefully attaching socket to the port 8080
	if (setsockopt(server->fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT,
			&opt, sizeof(opt)))
		err(EXIT_FAILURE, "Setsockopt Failed");

	// Forcefully attaching socket to the port 8080
	address.sin_family = AF_INET;
	address.sin_addr.s_addr = INADDR_ANY;
	address.sin_port = htons(ondemand_migration_port);
	if (bind(server->fd, (struct sockaddr *)&address,
			sizeof(address))<0)
		err(EXIT_FAILURE, "Bind Failed");

	// Listen for connection request
	if (listen(server->fd, 3) < 0)
			err(EXIT_FAILURE, "Listen Failed");

	printf("Remote page server listenning on port %d...\n",
			ondemand_migration_port);

	// Accept connection request
	if ((server->socket = accept(server->fd, (struct sockaddr *)&address,
			(socklen_t*)&addrlen))<0)
		err(EXIT_FAILURE, "Accept Failed");

	return server;
}

int receive_page_request(struct server_info *server, section_t *type,
		uint64_t *addr, uint8_t *npages) {
	int valread;
	struct packet recv_packet;

	// Read received data
    valread = read(server->socket , &recv_packet, sizeof(struct packet));
	if(valread != sizeof(struct packet)) {
		err(EXIT_FAILURE, "failed/short read (%d, shoud be %d) on page request "
				"reception", valread, sizeof(struct packet));
		return -1;
	}

	*type = recv_packet.type;
	*addr = recv_packet.address;
	*npages = recv_packet.npages;

	return 0;
}

uint64_t guest_virt_to_phys(uint64_t vaddr) {
#ifdef __aarch64__
		return aarch64_virt_to_phys(vaddr);
#else
		struct kvm_translation kt;
		kt.linear_address = vaddr;
		kvm_ioctl(vcpufd, KVM_TRANSLATE, &kt);
		return kt.physical_address;
#endif
}

int send_page_response(int sock, uint64_t vaddr, uint8_t npages) {
	char *buffer = malloc(npages * PAGE_SIZE);

	/* Fill buffer with pages from vaddr then send it */
	for(int i=0; i<npages; i++) {
		uint64_t paddr = guest_virt_to_phys(vaddr+i*PAGE_SIZE);
		memcpy(buffer + i*PAGE_SIZE, guest_mem + paddr, PAGE_SIZE);
	}

	if(send(sock, buffer, PAGE_SIZE*npages, 0) == -1)
		err(EXIT_FAILURE, "Remote server cannot send page data");

	free(buffer);
	return 0;
}

void handle_broken_pipe() {
	run_server = 0;
}

int on_demand_page_migration(uint64_t heap_size, uint64_t bss_size) {
	const char* file_name;
	int ret = 0;
	section_t req_type;
	uint64_t req_addr;
	uint8_t npages;

	signal(SIGPIPE, handle_broken_pipe);

	struct server_info *server = setup_page_response_server();

	printf("Client connected!\n");
	fflush(stdout);

	while(run_server) {
		receive_page_request(server, &req_type, &req_addr, &npages);
#if 0
		printf("Packet received, type: %s, addr: 0x%llu, npages: %u\n",
				(req_type == SECTION_HEAP) ? "heap" : "bss", req_addr, npages);
#endif
		switch(req_type) {
			case SECTION_BSS:
				bss_size -= PAGE_SIZE;
				break;

			case SECTION_HEAP:
				heap_size -= PAGE_SIZE;
				break;

			default:
				fprintf(stderr, "Unsupported Request Type. Closing server.\n");
				ret = -1;
				goto clean;
		}

		if(send_page_response(server->socket, req_addr,	npages) == -1) {
			ret = -1;
			goto clean;
		}

		if(heap_size <= 0)// && bss_size <=0)
			break;
	}

clean:
	printf("Closing Server\n");
	close(server->fd);
	close(server->socket);
	free(server);

	return ret;
}

/*-------------------------- Client Side Code --------------------------------*/

int connect_to_page_response_server()
{
	struct sockaddr_in address;
	int sock = 0, valread;
	struct sockaddr_in serv_addr;

	const char* server_ip = getenv("HERMIT_MIGRATE_SERVER");
	if(!server_ip) {
		printf("Please provide with server ip (HERMIT_MIGRATE_SERVER env. "
				"variable\n");
		return -1;
	}

	if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		perror("Socket creation error");
		return -1;
	}

	memset(&serv_addr, '0', sizeof(serv_addr));
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_port = htons(ondemand_migration_port);

	// Convert IPv4 and IPv6 addresses from text to binary form
	if(inet_pton(AF_INET, server_ip, &serv_addr.sin_addr)<=0) {
		perror("Invalid address/ Address not supported");
		close(sock);
		return -1;
	}

	if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
		perror("Connection Failed");
		close(sock);
		return -1;
	}

	return sock;
}

int send_page_request(section_t type, uint64_t address, char *buffer,
		uint8_t npages) {
	int valread, i;
	size_t size = 0;
	struct packet send_packet;

	send_packet.type = type;
	send_packet.address = address;
	send_packet.npages = npages;
	if(send(client_socket, (const void*)(&send_packet), sizeof(struct packet),
				0) == -1)
		err(EXIT_FAILURE, "Page request send failed.");

	int total_sz = PAGE_SIZE*npages;
	while(size < total_sz)	{
		valread = recv(client_socket ,(void*)(buffer+size), total_sz-size, 0);
		if(valread == -1) {
			perror("Page receive failed");
			return -1;
		}

		size += valread;
	}

	return 0;
}
