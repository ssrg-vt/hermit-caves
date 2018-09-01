#define _XOPEN_SOURCE 500 /* for pread */

#include "uhyve-remote-mem.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>

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

/* For now we only support the 'file' remote heap provider, which involves
 * dumping the applications state to a file and having it shared on NFS between
 * host and target */
#define HEAP_PROVIDER_FILE	0
#define HEAP_PROVIDER_NET	1
#define HEAP_PROVIDER		HEAP_PROVIDER_NET

#define PAGE_SIZE_HEAP		4096

static int heap_file_fd;
static chkpt_metadata_t md;
extern uint8_t* guest_mem;
extern int client_socket;

static int rmem_heap_file_init(const char *mdata_file_path,
		const char *heap_file_path) {

	int mdata_fd;

	heap_file_fd = open(heap_file_path, O_RDONLY, 0);
	if(heap_file_fd == -1) {
		perror("opening heap file");
		return -1;
	}

	mdata_fd = open(mdata_file_path, O_RDONLY, 0);
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
	return 0;
}

static int rmem_heap_net_init(const char *mdata_file_path) {

	int mdata_fd;

	mdata_fd = open(mdata_file_path, O_RDONLY, 0);
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

	return 0;
}

int rmem_init(void) {
#if HEAP_PROVIDER == HEAP_PROVIDER_FILE
	return rmem_heap_file_init(CHKPT_MDATA_FILE, CHKPT_HEAP_FILE);
#else
	if((client_socket = connect_to_page_response_server()) == -1)
		return -1;

	return rmem_heap_net_init(CHKPT_MDATA_FILE);
#endif
}

static int rmem_heap_file_end(void) {
	close(heap_file_fd);
	return 0;
}

/* TODO */
static int rmem_heap_net_end(void) {
	close(client_socket);
	return 0;//-ENOSYS;
}

int rmem_end(void) {
#if HEAP_PROVIDER == HEAP_PROVIDER_FILE
	return rmem_heap_file_end();
#else
	return rmem_heap_net_end();
#endif

}

int rmem_heap_file(uint64_t vaddr, uint64_t paddr) {
	uint64_t page_floor = vaddr - (vaddr % PAGE_SIZE_HEAP);
	uint64_t heap_offset = page_floor - md.heap_start;

	if(pread(heap_file_fd, guest_mem + paddr, PAGE_SIZE_HEAP, heap_offset) !=
			PAGE_SIZE_HEAP) {
		fprintf(stderr, "Cannot read heap file at offset 0x%x\n", heap_offset);
		return -1;
	}

	return 0;
}

int rmem_heap_net(uint64_t vaddr, uint64_t paddr) {
	uint64_t page_floor = vaddr - (vaddr % PAGE_SIZE_HEAP);
	uint64_t heap_offset = page_floor - md.heap_start;

	send_page_request(SECTION_HEAP, heap_offset, guest_mem+paddr);

	return 0;
}

int rmem_heap(uint64_t vaddr, uint64_t paddr) {
#if HEAP_PROVIDER == HEAP_PROVIDER_FILE
	return rmem_heap_file(vaddr, paddr);
#else
	return rmem_heap_net(vaddr, paddr);
#endif
}
