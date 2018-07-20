#ifndef UHYVE_MIGRATION_H
#define UHYVE_MIGRATION_H

#include <stdint.h>
#include <stddef.h>

void set_migrate_flag_addr(uint64_t addr);
int register_migration_signal(void);
int test_migration(int sec);

#endif /* UHYVE_MIGRATION_H */
