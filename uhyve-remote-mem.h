#ifndef UHYVE_REMOTE_MEM_H
#define UHYVE_REMOTE_MEM_H

#include <stdint.h>

#include "uhyve-syscalls.h"

int rmem_init(uint64_t heap_size, uint64_t bss_size, uint64_t data_size);
int rmem(pfault_type_t type, uint64_t vaddr, char *buf, uint8_t npages,
		uint64_t page_size);

#endif /* UHYVE_REMOTE_MEM_H */
