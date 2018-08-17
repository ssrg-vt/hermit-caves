#ifndef UHYVE_REMOTE_MEM_H
#define UHYVE_REMOTE_MEM_H

#include <stdint.h>

int rmem_heap(uint64_t vaddr, uint64_t paddr);
int rmem_init(void);

#endif /* UHYVE_REMOTE_MEM_H */
