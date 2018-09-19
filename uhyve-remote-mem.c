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

extern uint8_t* guest_mem;
extern int client_socket;
static int64_t heap_size_left, bss_size_left, data_size_left;

int rmem_init(uint64_t heap_size, uint64_t bss_size, uint64_t data_size) {

	if((client_socket = connect_to_page_response_server()) == -1)
		return -1;

	/* Heap is always mapped with 4KB pages */
	heap_size_left = PAGE_CEIL(heap_size);

	/* BSS and data are mapped with different page sizes on ARM and x86 */
#ifdef __aarch64__
	data_size_left = PAGE_CEIL(data_size);
	bss_size_left = PAGE_CEIL(bss_size);
#else
	data_size_left = HUGE_PAGE_CEIL(data_size);
	bss_size_left = HUGE_PAGE_CEIL(bss_size);
#endif

	return 0;
}

static int rmem_end(void) {
	close(client_socket);
	return 0;
}

int rmem(pfault_type_t type, uint64_t vaddr, char *buf, uint8_t npages,
		uint64_t page_size) {
	int ret = send_page_request(type, vaddr, buf, npages, page_size);

	if(type == PFAULT_HEAP)
		heap_size_left -= npages*page_size;
	else if(type == PFAULT_BSS)
		bss_size_left -= npages*page_size;
	else
		data_size_left -= npages*page_size;

#if 0
	char *type_str;

	if(type == PFAULT_HEAP)
		type_str = "heap";
	else if(type == PFAULT_BSS)
		type_str = "bss";
	else
		type_str = "data";

	printf("Req %d pages from %s left heap: %lld, bss: %lld, data: %lld\n",
			npages, type_str, heap_size_left, bss_size_left, data_size_left);
#endif

	if(heap_size_left <= 0  && bss_size_left <= 0 && data_size_left <= 0)
		rmem_end();

	return ret;
}

