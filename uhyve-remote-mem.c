#define _XOPEN_SOURCE 500  /* For pread, TODO remove file support */

#include "uhyve-remote-mem.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>

#include "uhyve-het-migration.h"
#include "uhyve-het-migration-ondemand.h"

/* Hack to avoid two definitions of chkpt_metadata_t (and the default
 * checkpoint filenames). it's not ideal, maybe there is a better solution.
 * Note that the order here is important, for example migration-chkpt.h needs
 * some typedefs from migration-x86-regs.h */
#define MAX_TASKS			32
typedef unsigned int 		tid_t;
#include "../include/hermit/migration-x86-regs.h"
#include "../include/hermit/migration-aarch64-regs.h"
#include "../include/hermit/migration-chkpt.h"

/* We support:
 * - the 'file' remote heap provider, which involves dumping the applications
 *   state to a file and having it shared on NFS between host and target
 * - the 'net' which sets up a tcp/ip connection between the host and target
 *   and serves pages requests directly from the source guest memory */
#define HEAP_PROVIDER_FILE	0
#define HEAP_PROVIDER_NET	1
#define HEAP_PROVIDER		HEAP_PROVIDER_NET

#define PAGE_SIZE_HEAP		4096

static int heap_file_fd;
static chkpt_metadata_t md;
static uint64_t remote_size_left;
extern uint8_t* guest_mem;
extern int client_socket;

static int rmem_heap_file_init(const char *heap_file_path) {

	heap_file_fd = open(heap_file_path, O_RDONLY, 0);
	if(heap_file_fd == -1) {
		perror("opening heap file");
		return -1;
	}

	return 0;
}

static int rmem_heap_net_init() {

	remote_size_left += md.heap_size;

	return 0;
}

static int rmem_bss_net_init() {

	remote_size_left += md.bss_size;

	return 0;
}

static int rmem_data_net_init() {

	remote_size_left += md.data_size;

	return 0;
}

int rmem_init(void) {

	int mdata_fd;

	mdata_fd = open(CHKPT_MDATA_FILE, O_RDONLY, 0);
	if(mdata_fd == -1) {
		perror("opening mdata file");
		return -1;
	}

	if(read(mdata_fd, &md, sizeof(chkpt_metadata_t)) !=
			sizeof(chkpt_metadata_t)) {
		perror("reading mdata");
		return -1;
	}

	close(mdata_fd);

#if HEAP_PROVIDER == HEAP_PROVIDER_FILE
	return rmem_heap_file_init(CHKPT_HEAP_FILE);
#else

	char *str = getenv("HERMIT_MIGRATE_SERVER");
	if(!str || !atoi(str))
		return 0;

	if((client_socket = connect_to_page_response_server()) == -1)
		return -1;

	if(rmem_heap_net_init() < 0)
		return -1;

	if(rmem_bss_net_init() < 0)
		return -1;

	if(rmem_data_net_init() < 0)
		return -1;

	return 0;
#endif
}

static int rmem_heap_file_end(void) {
	close(heap_file_fd);
	return 0;
}

int rmem_end(void) {
#if HEAP_PROVIDER == HEAP_PROVIDER_FILE
	return rmem_heap_file_end();
#else
	close(client_socket);
	return 0;
#endif
}

int rmem_heap_file(uint64_t vaddr, uint64_t paddr, int npages) {
	uint64_t page_floor = vaddr - (vaddr % PAGE_SIZE_HEAP);
	uint64_t heap_offset = page_floor - md.heap_start;

	if(pread(heap_file_fd, guest_mem + paddr, PAGE_SIZE_HEAP*npages,
				heap_offset) != PAGE_SIZE_HEAP) {
		fprintf(stderr, "Cannot read heap file at offset 0x%x\n", heap_offset);
		return -1;
	}

	return 0;
}

int rmem_heap_net(uint64_t vaddr, uint64_t paddr, uint8_t npages, uint32_t page_size) {
	return send_page_request(AREA_HEAP, vaddr, guest_mem+paddr, npages, page_size);
}

int rmem_bss_net(uint64_t vaddr, uint64_t paddr, uint8_t npages, uint32_t page_size) {
	return send_page_request(AREA_BSS, vaddr, guest_mem+paddr, npages, page_size);
}

int rmem_data_net(uint64_t vaddr, uint64_t paddr, uint8_t npages, uint32_t page_size) {
	return send_page_request(AREA_DATA, vaddr, guest_mem+paddr, npages, page_size);
}

int rmem_heap(uint64_t vaddr, uint64_t paddr, uint8_t npages, uint32_t page_size) {
	int ret;
#if HEAP_PROVIDER == HEAP_PROVIDER_FILE
	ret = rmem_heap_file(vaddr, paddr, npages);
#else
	ret = rmem_heap_net(vaddr, paddr, npages, page_size);
#endif

	/* If we transferred the entire data set, close the connection FIXME this
	 * only works for heap now */
	remote_size_left -= npages*page_size;
	if(!remote_size_left) {
#if HEAP_PROVIDER_FILE == HEAP_PROVIDER_NET
		client_exit();
#endif
		/* Popcorn: update status to ready for migration */
		het_migration_set_status(STATUS_READY_FOR_MIGRATION);
		rmem_end();
	}

	return ret;
}

int rmem_bss(uint64_t vaddr, uint64_t paddr, uint8_t npages, uint32_t page_size) {
	int ret;
#if HEAP_PROVIDER == HEAP_PROVIDER_FILE
#else
	ret = rmem_bss_net(vaddr, paddr, npages, page_size);
#endif

	/* If we transferred the entire data set, close the connection. */
	remote_size_left -= npages*page_size;
	if(!remote_size_left) {
		/* Popcorn: update status to ready for migration */
		het_migration_set_status(STATUS_READY_FOR_MIGRATION);
		rmem_end();
	}

	return ret;
}

int rmem_data(uint64_t vaddr, uint64_t paddr, uint8_t npages, uint32_t page_size) {
	int ret;
#if HEAP_PROVIDER == HEAP_PROVIDER_FILE
#else
	ret = rmem_data_net(vaddr, paddr, npages, page_size);
#endif

	/* If we transferred the entire data set, close the connection. */
	remote_size_left -= npages*page_size;
	if(!remote_size_left) {
		/* Popcorn: update status to ready for migration */
		het_migration_set_status(STATUS_READY_FOR_MIGRATION);
		rmem_end();
	}

	return ret;
}
