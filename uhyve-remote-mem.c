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

#define PAGE_SIZE_HEAP		4096

static chkpt_metadata_t md;
static uint64_t remote_size_left;
extern uint8_t* guest_mem;
extern int client_socket;

static int rmem_net_init(uint64_t heap_size, uint64_t bss_size,
		uint64_t data_size) {
	remote_size_left = heap_size + bss_size + data_size;
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

	char *str = getenv("HERMIT_MIGRATE_SERVER");
	if(!str || !atoi(str))
		return 0;

	if((client_socket = connect_to_page_response_server()) == -1)
		return -1;

	if(rmem_net_init(md.heap_size, md.bss_size, md.data_size))
		return -1;

	return 0;
}

int rmem_end(void) {
	close(client_socket);
	return 0;
}

int rmem_heap_net(uint64_t vaddr, uint64_t paddr, uint8_t npages, uint32_t page_size) {
	return send_page_request(PFAULT_HEAP, vaddr, guest_mem+paddr, npages, page_size);
}

int rmem_bss_net(uint64_t vaddr, uint64_t paddr, uint8_t npages, uint32_t page_size) {
	return send_page_request(PFAULT_BSS, vaddr, guest_mem+paddr, npages, page_size);
}

int rmem_data_net(uint64_t vaddr, uint64_t paddr, uint8_t npages, uint32_t page_size) {
	return send_page_request(PFAULT_DATA, vaddr, guest_mem+paddr, npages, page_size);
}

int rmem_heap(uint64_t vaddr, uint64_t paddr, uint8_t npages, uint32_t page_size) {
	int ret;
	ret = rmem_heap_net(vaddr, paddr, npages, page_size);

	/* If we transferred the entire data set, close the connection FIXME this
	 * only works for heap now */
	remote_size_left -= npages*page_size;
	if(!remote_size_left) {
		client_exit();
		/* Popcorn: update status to ready for migration */
		het_migration_set_status(STATUS_READY_FOR_MIGRATION);
		rmem_end();
	}

	return ret;
}

int rmem_bss(uint64_t vaddr, uint64_t paddr, uint8_t npages, uint32_t page_size) {
	int ret;
	ret = rmem_bss_net(vaddr, paddr, npages, page_size);

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
	ret = rmem_data_net(vaddr, paddr, npages, page_size);

	/* If we transferred the entire data set, close the connection. */
	remote_size_left -= npages*page_size;
	if(!remote_size_left) {
		/* Popcorn: update status to ready for migration */
		het_migration_set_status(STATUS_READY_FOR_MIGRATION);
		rmem_end();
	}

	return ret;
}
