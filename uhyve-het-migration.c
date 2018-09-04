#define _XOPEN_SOURCE 600

#include "uhyve-het-migration.h"
#include <stdint.h>
#include <stdio.h>
#include <time.h>
#include <signal.h>
#include <sys/file.h>
#include <unistd.h>
#include <err.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>

#define HET_MIGRATION_STATUS_FILE	".status"
#define MIGRATION_SIGNAL			SIGUSR1

/* TODO find a clean way to make this architecture-agnostic */
typedef struct { volatile int32_t counter; } atomic_int32_t;
static atomic_int32_t *migrate_flag;

static void set_migrate_flag(void) {
	int32_t ret = 1;
	atomic_int32_t *d = migrate_flag;
#ifdef __aarch64__
	__asm__ volatile(
		"%=:\n\t"
		"ldxr w0, %0\n\t"
		"ldr w1, %1\n\t"
		"str w0, %1\n\t"
		"stxr w1, w1, %0\n\t"
		"cbnz w1, %=b"
		: "+Q"(d->counter), "+m"(ret)
		:
		: "memory", "w0", "w1");
#else /* __x86_64 */
	__asm__ volatile ("xchgl %0, %1" : "=r"(ret) : "m"(d->counter),
		"0"(ret) : "memory");
#endif
}

void set_migrate_flag_addr(uint64_t addr) {
	migrate_flag = (atomic_int32_t *)(addr);
}

void migrate_signal_handler(int signum) {
	set_migrate_flag();
}

int register_migration_signal(void) {

	signal(MIGRATION_SIGNAL, &migrate_signal_handler);

	if(signal(MIGRATION_SIGNAL, migrate_signal_handler) == SIG_ERR) {
		perror("signal");
		return -1;
	}

	return 0;
}

/* fire MIGRATION_SIGNAL after sec seconds, this is done with a one-shot timer
 * */
int test_migration(int sec) {
	timer_t timerid;
	struct sigaction sa;
	struct sigevent sev;
	struct itimerspec its;

	/* prepare sigaction */
	sa.sa_flags = 0x0;
	sa.sa_handler = &migrate_signal_handler;
	sigemptyset(&sa.sa_mask);
	if(sigaction(MIGRATION_SIGNAL, &sa, NULL) == -1) {
		perror("sigaction");
		return -1;
	}

	/* timer */
	sev.sigev_notify = SIGEV_SIGNAL;
	sev.sigev_signo = MIGRATION_SIGNAL;
	if(timer_create(CLOCK_REALTIME, &sev, &timerid) == -1) {
		perror("timer_create");
		return -1;
	}

	/* start timer */
	its.it_value.tv_sec = sec;
	its.it_value.tv_nsec = 0;
	its.it_interval.tv_sec = 0;		/* one shot */
	its.it_interval.tv_nsec = 0;	/* one shot */
	if(timer_settime(timerid, 0, &its, NULL) == -1) {
		perror("timer_settime");
		return -1;
	}

	return 0;
}

/* status should be one of the defines in uhyve-het-migration.h */
int het_migration_set_status(het_migration_status_t status) {
	int fd;
	char *status_str;
	char str[128];
	struct timeval ts;

	gettimeofday(&ts, NULL);

	/* Create the status file if it does not exists */
	if(access(HET_MIGRATION_STATUS_FILE, F_OK) == -1)
		fd = open(HET_MIGRATION_STATUS_FILE, O_WRONLY | O_CREAT, 0777);
	else
		fd = open(HET_MIGRATION_STATUS_FILE, O_WRONLY | O_APPEND, 0x0);

	if(fd == -1)
		err(EXIT_FAILURE, "Cannot open/create status file");

	flock(fd, LOCK_EX);

	switch(status) {
		case STATUS_NOT_RUNNING:
			status_str = "STATUS_NOT_RUNNING";
			break;
		case STATUS_RESTORING_CHKPT:
			status_str = "STATUS_RESTORING_CHKPT";
			break;
		case STATUS_PULLING_PAGES:
			status_str = "STATUS_PULLING_PAGES";
			break;
		case STATUS_READY_FOR_MIGRATION:
			status_str = "STATUS_READY_FOR_MIGRATION";
			break;
		case STATUS_CHECKPOINTING:
			status_str = "STATUS_CHECKPOINTING";
			break;
		case STATUS_SERVING_PAGES:
			status_str = "STATUS_SERVING_REMOTE_PAGES";
			break;
		default:
			err(EXIT_FAILURE, "Wrong status!");
	}

	sprintf(str, "%ld.%06ld:%s\n", ts.tv_sec, ts.tv_usec, status_str);

	if(write(fd, str, strlen(str)) != strlen(str))
		err(EXIT_FAILURE, "Short write in status file");

	flock(fd, LOCK_UN);
	close(fd);
}
