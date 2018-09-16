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

static chkpt_metadata_t md;
static int64_t remote_size_left;
extern uint8_t* guest_mem;
extern int client_socket;

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

	if((client_socket = connect_to_page_response_server()) == -1)
		return -1;

	remote_size_left = md.heap_size + md.bss_size + md.data_size;

	return 0;
}

static int rmem_end(void) {
	close(client_socket);
	return 0;
}

int rmem(pfault_type_t type, uint64_t vaddr, char *buf, uint8_t npages,
		uint64_t page_size) {
	int ret = send_page_request(type, vaddr, buf, npages, page_size);

	remote_size_left -= npages*page_size;
	if(remote_size_left <= 0)
		rmem_end();

	return ret;
}

