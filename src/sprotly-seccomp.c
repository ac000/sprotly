/*
 * sprotly-seccomp.c
 *
 * Copyright (c) 2017		Securolytics, Inc.
 *				Andrew Clayton <andrew.clayton@securolytics.io>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 */

#define _GNU_SOURCE

#include <sys/socket.h>
#include <signal.h>
#include <fcntl.h>
#include <errno.h>

#ifdef _HAVE_LIBSECCOMP
#include <seccomp.h>
#endif

#include <libac.h>

#include "sprotly.h"
#include "proxy.h"

extern int access_log_fd;
extern int error_log_fd;
extern const char *access_log;
extern const char *error_log;
extern const char *sprotly_pid_file;
extern ac_slist_t *listen_fds;

void init_seccomp(void)
{
#ifdef _HAVE_LIBSECCOMP
	scmp_filter_ctx sec_ctx;
	ac_slist_t *list = listen_fds;
	int err;

	sec_ctx = seccomp_init(SCMP_ACT_ERRNO(EACCES));
	if (sec_ctx == NULL) {
		logit("seccomp_init() failed. Continuing without seccomp\n");
		return;
	}

	/* Allow unrestricted opening of the log files */
	seccomp_rule_add(sec_ctx, SCMP_ACT_ALLOW, SCMP_SYS(open), 1,
			SCMP_A0(SCMP_CMP_EQ, (scmp_datum_t)access_log));
	seccomp_rule_add(sec_ctx, SCMP_ACT_ALLOW, SCMP_SYS(open), 1,
			SCMP_A0(SCMP_CMP_EQ, (scmp_datum_t)error_log));
	/* Allow opening of other files read-only */
	seccomp_rule_add(sec_ctx, SCMP_ACT_ALLOW, SCMP_SYS(open), 1,
			SCMP_CMP(1, SCMP_CMP_MASKED_EQ, O_WRONLY | O_RDWR, 0));

	seccomp_rule_add(sec_ctx, SCMP_ACT_ALLOW, SCMP_SYS(close), 0);

	seccomp_rule_add(sec_ctx, SCMP_ACT_ALLOW, SCMP_SYS(read), 0);
	/*
	 * Restrict write access to the log files. Even after log file
	 * rotation they should still have the same fd numbers.
	 */
	seccomp_rule_add(sec_ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 1,
			SCMP_A0(SCMP_CMP_EQ, access_log_fd));
	seccomp_rule_add(sec_ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 1,
			SCMP_A0(SCMP_CMP_EQ, error_log_fd));

	seccomp_rule_add(sec_ctx, SCMP_ACT_ALLOW, SCMP_SYS(sendto), 0);
	seccomp_rule_add(sec_ctx, SCMP_ACT_ALLOW, SCMP_SYS(recvfrom), 0);

	seccomp_rule_add(sec_ctx, SCMP_ACT_ALLOW, SCMP_SYS(splice), 0);
	seccomp_rule_add(sec_ctx, SCMP_ACT_ALLOW, SCMP_SYS(pipe2), 0);

	/* Restrict chmod/chown to the log files */
	seccomp_rule_add(sec_ctx, SCMP_ACT_ALLOW, SCMP_SYS(chmod), 2,
			SCMP_A0(SCMP_CMP_EQ, (scmp_datum_t)LOG_PATH),
			SCMP_A1(SCMP_CMP_EQ, 0700));
	seccomp_rule_add(sec_ctx, SCMP_ACT_ALLOW, SCMP_SYS(chown), 1,
			SCMP_A0(SCMP_CMP_EQ, (scmp_datum_t)LOG_PATH));
	seccomp_rule_add(sec_ctx, SCMP_ACT_ALLOW, SCMP_SYS(chown), 1,
			SCMP_A0(SCMP_CMP_EQ, (scmp_datum_t)access_log));
	seccomp_rule_add(sec_ctx, SCMP_ACT_ALLOW, SCMP_SYS(chown), 1,
			SCMP_A0(SCMP_CMP_EQ, (scmp_datum_t)error_log));

	/* Allow to unlink the pid file */
	seccomp_rule_add(sec_ctx, SCMP_ACT_ALLOW, SCMP_SYS(unlinkat), 2,
			SCMP_A1(SCMP_CMP_EQ, (scmp_datum_t)sprotly_pid_file),
			SCMP_A2(SCMP_CMP_EQ, 0));

	seccomp_rule_add(sec_ctx, SCMP_ACT_ALLOW, SCMP_SYS(stat), 0);
	seccomp_rule_add(sec_ctx, SCMP_ACT_ALLOW, SCMP_SYS(fstat), 0);
	seccomp_rule_add(sec_ctx, SCMP_ACT_ALLOW, SCMP_SYS(fcntl), 0);

	seccomp_rule_add(sec_ctx, SCMP_ACT_ALLOW, SCMP_SYS(signalfd4), 0);
	seccomp_rule_add(sec_ctx, SCMP_ACT_ALLOW, SCMP_SYS(rt_sigprocmask), 0);
	seccomp_rule_add(sec_ctx, SCMP_ACT_ALLOW, SCMP_SYS(rt_sigaction), 0);
	seccomp_rule_add(sec_ctx, SCMP_ACT_ALLOW, SCMP_SYS(rt_sigreturn), 0);
	seccomp_rule_add(sec_ctx, SCMP_ACT_ALLOW, SCMP_SYS(pause), 0);

	/* Restrict kill to sending SIGHUP & SIGTERM to the children */
	seccomp_rule_add(sec_ctx, SCMP_ACT_ALLOW, SCMP_SYS(kill), 2,
			SCMP_A0(SCMP_CMP_EQ, 0), SCMP_A1(SCMP_CMP_EQ, SIGHUP));
	seccomp_rule_add(sec_ctx, SCMP_ACT_ALLOW, SCMP_SYS(kill), 2,
			SCMP_A0(SCMP_CMP_EQ, 0), SCMP_A1(SCMP_CMP_EQ, SIGTERM));
	seccomp_rule_add(sec_ctx, SCMP_ACT_ALLOW, SCMP_SYS(wait4), 0);

	seccomp_rule_add(sec_ctx, SCMP_ACT_ALLOW, SCMP_SYS(socket), 1,
			SCMP_CMP(1, SCMP_CMP_MASKED_EQ,
				SOCK_STREAM | SOCK_NONBLOCK,
				SOCK_STREAM | SOCK_NONBLOCK));
	/* Restrict accept4(2) to the listen socket(s) */
	while (list) {
		int fd = ((struct listen_fd *)list->data)->fd;

		seccomp_rule_add(sec_ctx, SCMP_ACT_ALLOW, SCMP_SYS(accept4), 1,
				SCMP_A0(SCMP_CMP_EQ, fd));
		list = list->next;
	}
	seccomp_rule_add(sec_ctx, SCMP_ACT_ALLOW, SCMP_SYS(connect), 0);
	seccomp_rule_add(sec_ctx, SCMP_ACT_ALLOW, SCMP_SYS(getsockopt), 0);

	seccomp_rule_add(sec_ctx, SCMP_ACT_ALLOW, SCMP_SYS(epoll_create1), 0);
	seccomp_rule_add(sec_ctx, SCMP_ACT_ALLOW, SCMP_SYS(epoll_ctl), 0);
	seccomp_rule_add(sec_ctx, SCMP_ACT_ALLOW, SCMP_SYS(epoll_wait), 0);

	seccomp_rule_add(sec_ctx, SCMP_ACT_ALLOW, SCMP_SYS(setgroups), 0);
	seccomp_rule_add(sec_ctx, SCMP_ACT_ALLOW, SCMP_SYS(setgid), 0);
	seccomp_rule_add(sec_ctx, SCMP_ACT_ALLOW, SCMP_SYS(setuid), 0);

	seccomp_rule_add(sec_ctx, SCMP_ACT_ALLOW, SCMP_SYS(nanosleep), 0);

	seccomp_rule_add(sec_ctx, SCMP_ACT_ALLOW, SCMP_SYS(clone), 0);

	seccomp_rule_add(sec_ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit), 0);
	seccomp_rule_add(sec_ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit_group), 0);

	err = seccomp_load(sec_ctx);
	if (!err)
		logit("Initialised seccomp\n");
	else
		logit("seccomp_load() failed. Continuing without seccomp\n");

	seccomp_release(sec_ctx);

#else
	logit("Not using seccomp\n");
#endif
}
