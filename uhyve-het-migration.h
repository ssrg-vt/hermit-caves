#ifndef UHYVE_MIGRATION_H
#define UHYVE_MIGRATION_H

#include <stdint.h>
#include <stddef.h>

/* The different states a unikernel can take. Be sure to edit
 * het_migration_set_status when adding/removing states */
typedef enum {
	STATUS_NOT_RUNNING 	= 0,
	STATUS_PULLING_PAGES,
	STATUS_READY_FOR_MIGRATION,
	STATUS_CHECKPOINTING,
	STATUS_SERVING_PAGES
} het_migration_status_t;

void set_migrate_flag_addr(uint64_t addr);
int register_migration_signal(void);
int test_migration(int sec);
int het_migration_set_status(het_migration_status_t status);

#endif /* UHYVE_MIGRATION_H */
