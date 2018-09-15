#ifndef UHYVE_REMOTE_MEM_H
#define UHYVE_REMOTE_MEM_H

#include <stdint.h>

int rmem_heap(uint64_t vaddr, uint64_t paddr, uint8_t npages, uint32_t page_size);
int rmem_bss(uint64_t vaddr, uint64_t paddr, uint8_t npages, uint32_t page_size);
int rmem_data(uint64_t vaddr, uint64_t paddr, uint8_t npages, uint32_t page_size);
int rmem_init(void);

#endif /* UHYVE_REMOTE_MEM_H */
