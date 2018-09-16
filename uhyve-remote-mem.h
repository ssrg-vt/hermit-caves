#ifndef UHYVE_REMOTE_MEM_H
#define UHYVE_REMOTE_MEM_H

#include <stdint.h>

#include "uhyve-syscalls.h"

int rmem_init(void);
int rmem(pfault_type_t type, uint64_t vaddr, char *buf, uint8_t npages,
		uint64_t page_size);

#endif /* UHYVE_REMOTE_MEM_H */
