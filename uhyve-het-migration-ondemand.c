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
#include <errno.h>

#include "uhyve.h"
#include "uhyve-het-migration-ondemand.h"

#define CHKPT_MDATA_FILE	"mdata.bin"
#define CHKPT_STACK_FILE	"stack.bin"
#define CHKPT_BSS_FILE		"bss.bin"
#define CHKPT_DATA_FILE		"data.bin"
#define CHKPT_HEAP_FILE		"heap.bin"
#define CHKPT_TLS_FILE		"tls.bin"
#define CHKPT_FDS_FILE		"fds.bin"

#define NI_MAXHOST 	1025

/* Set to 1 to log in a local file, rmem.log, the memory accesses */
#define TRACE_RMEM_ACCESS	0
#define TRACE_RMEM_FILE 	"rmem.log"

/* Set to 1 to time the time of a page/set of pages transfer. WARNING: this
 * impacts the general performance but it is not intrusive to what it is suppose
 * to measure */
#define TIME_ROUND_TRIP		0
#define ROUND_TRIP_FILE		"roundtrip.log"
static int round_trip_fd = -1;

extern int client_socket;
extern __thread int vcpufd;
extern uint64_t aarch64_virt_to_phys(uint64_t vaddr);

static char run_server = 1;

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
	fflush(stdout);

	// Accept connection request
	if ((server->socket = accept(server->fd, (struct sockaddr *)&address,
			(socklen_t*)&addrlen))<0)
		err(EXIT_FAILURE, "Accept Failed");

	return server;
}

/* Returns:
 * 0 on success (page request served)
 * -1 on error
 * 1 if the remote client exited normally
 */
int receive_page_request(struct server_info *server, pfault_type_t *type,
		uint64_t *addr, uint8_t *npages, uint64_t *page_size) {
	int valread;
	struct packet recv_packet;

	// Read received data
	valread = read(server->socket , &recv_packet, sizeof(struct packet));
	if(valread != sizeof(struct packet)) {
		/* This may indicate that the client simply finished execution - FIXME
		 * there might be other error conditions here that are actually valid
		 * execution */
		if(valread == 0 && (errno == ENOENT || errno == EINTR)) {
			printf("Client exited\n");
			run_server = 0;
			return 1;
		}

		err(EXIT_FAILURE, "failed/short read (%d, shoud be %d) on page request "
				"reception", valread, sizeof(struct packet));
		return -1;
	}

	*type = recv_packet.type;
	*addr = recv_packet.address;
	*npages = recv_packet.npages;
	*page_size = recv_packet.page_size;

	return 0;
}

uint64_t guest_virt_to_phys(uint64_t vaddr) {
#ifdef __aarch64__
	/* aarch64 does not support KVM_TRANSLATE, so we have to manually walk the
	 * page table from the host */
	return aarch64_virt_to_phys(vaddr);
#else
	struct kvm_translation kt;
	kt.linear_address = vaddr;
	kvm_ioctl(vcpufd, KVM_TRANSLATE, &kt);
	return kt.physical_address;
#endif
}

int send_page_response(int sock, uint64_t vaddr, uint8_t npages, uint64_t page_size) {
	char *buffer = malloc(npages * page_size);

	/* Fill buffer with pages from vaddr then send it */
	for(int i=0; i<npages; i++) {
		uint64_t paddr = guest_virt_to_phys(vaddr + i*page_size);
		memcpy(buffer + i * page_size, guest_mem + paddr, page_size);
	}

	if(send(sock, buffer, page_size*npages, 0) == -1)
		err(EXIT_FAILURE, "Remote server cannot send page data");

	free(buffer);
	return 0;
}

void handle_broken_pipe() {
	run_server = 0;
}

int on_demand_page_migration(uint64_t heap_size, uint64_t bss_size, uint64_t data_size) {
	const char* file_name;
	int ret = 0;
	pfault_type_t req_type;
	uint64_t req_addr;
	uint8_t npages;
	uint64_t page_size;

	heap_size = PAGE_CEIL(heap_size);
	/* WARNING: we are on the server side here so sizes are inverted ! */
#ifdef __x86_64__
	data_size = PAGE_CEIL(data_size);
	bss_size = PAGE_CEIL(bss_size);
#else
	data_size = HUGE_PAGE_CEIL(data_size);
	bss_size = HUGE_PAGE_CEIL(bss_size);
#endif
	int64_t initial_heap_size = heap_size;
	int64_t initial_bss_size = bss_size;
	int64_t initial_data_size = data_size;

	signal(SIGPIPE, handle_broken_pipe);

	struct server_info *server = setup_page_response_server();

#if TRACE_RMEM_ACCESS == 1
	struct timeval rmem_ts_begin;
	int rmem_trace_fd = open(TRACE_RMEM_FILE, O_WRONLY | O_TRUNC | O_CREAT,
			S_IRWXU);
	if(rmem_trace_fd == -1) {
		fprintf(stderr, "Cannot open %s\n", TRACE_RMEM_FILE);
		return -1;
	}
	gettimeofday(&rmem_ts_begin, NULL);
#endif

	printf("Client connected!\n");
	fflush(stdout);

	while(run_server) {
		receive_page_request(server, &req_type, &req_addr, &npages, &page_size);
#if 0
		char *type_str;
		if(req_type == PFAULT_HEAP)
			type_str = "heap";
		else if (req_type == PFAULT_BSS)
			type_str = "bss";
		else if (req_type == PFAULT_DATA)
			type_str = "data";
		else
			type_str = "?";

		printf("Packet received, type: %s, addr: 0x%llu, npages: %u, "
				"psize: %llu\n", type_str, req_addr, npages, page_size);
#endif
		switch(req_type) {
			case PFAULT_BSS:
				bss_size -= page_size*npages;
				break;

			case PFAULT_DATA:
				data_size -= page_size*npages;
				break;

			case PFAULT_HEAP:
				heap_size -= page_size*npages;
				break;

			default:
				fprintf(stderr, "Unsupported Request Type. Closing server.\n");
				ret = -1;
				goto clean;
		}

#if TRACE_RMEM_ACCESS == 1
		char rmem_str[128];
		struct timeval ts, ts_relative;
		gettimeofday(&ts, NULL);
		timersub(&ts, &rmem_ts_begin, &ts_relative);
		/* Format: timestamp; address; number of pages; heap size left to
		 * serve (bytes);  heap size left to serve (%); bss size left to serve
		 * (bytes); bss size left to serve (%); data size left to serve (bytes);
		 * data size left to serve (%) */
		int heap_pct = (heap_size*100)/initial_heap_size;
		int bss_pct = (bss_size*100)/initial_bss_size;
		int data_pct = (data_size*100)/initial_data_size;
		sprintf(rmem_str, "%ld.%06ld;%llu;%u;%lld;%d;%lld;%d;%lld;%d\n",
				ts_relative.tv_sec, ts_relative.tv_usec, req_addr, npages,
				heap_size, heap_pct, bss_size, bss_pct, data_size, data_pct);
		if(write(rmem_trace_fd, rmem_str, strlen(rmem_str)) != strlen(rmem_str))
			err(EXIT_FAILURE, "Issue writing in %s\n", TRACE_RMEM_FILE);
#endif
		ret = send_page_response(server->socket, req_addr, npages, page_size);
		if(ret == -1)
			goto clean;

		if(!heap_size && !bss_size && !data_size) {
			printf("Full remote memory served\n");
			break;
		}
	}

clean:
#if TRACE_RMEM_ACCESS == 1
	close(rmem_trace_fd);
#endif
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

int client_exit(void) {
#if TIME_ROUND_TRIP
	close(round_trip_fd);
#endif
	return 0;
}

int send_page_request(pfault_type_t type, uint64_t address, char *buffer,
		uint8_t npages, uint32_t page_size) {
	int valread, i;
	size_t size = 0;
	struct packet send_packet;

	send_packet.type = type;
	send_packet.address = address;
	send_packet.npages = npages;
	send_packet.page_size = page_size;

#if TIME_ROUND_TRIP == 1
	if(round_trip_fd == -1)
		round_trip_fd = open(ROUND_TRIP_FILE, O_WRONLY | O_TRUNC | O_CREAT,
				S_IRWXU);
	if(round_trip_fd == -1)
		err(EXIT_FAILURE, "Cannot open %s", ROUND_TRIP_FILE);

	struct timeval start;
	gettimeofday(&start, NULL);
#endif

	if(send(client_socket, (const void*)(&send_packet), sizeof(struct packet),
				0) == -1)
		err(EXIT_FAILURE, "Page request send failed.");

	int total_sz = page_size*npages;
	while(size < total_sz)	{
		valread = recv(client_socket ,(void*)(buffer+size), total_sz-size, 0);
		if(valread == -1) {
			perror("Page receive failed");
			return -1;
		}

		size += valread;
	}

#if TIME_ROUND_TRIP == 1
	char str[32];
	struct timeval stop, total;
	gettimeofday(&stop, NULL);
	timersub(&stop, &start, &total);
	sprintf(str, "%u;%ld.%06ld\n", npages, total.tv_sec, total.tv_usec);
	if(write(round_trip_fd, str, strlen(str)) != strlen(str))
		err(EXIT_FAILURE, "Cannot write in %s", ROUND_TRIP_FILE);
#endif

	return 0;
}
