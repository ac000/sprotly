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

#include <errno.h>

#ifdef _HAVE_LIBSECCOMP
#include <seccomp.h>
#endif

#include "sprotly.h"

extern int access_log_fd;

void init_seccomp(void)
{
#ifdef _HAVE_LIBSECCOMP
	scmp_filter_ctx sec_ctx;
	int err;

	sec_ctx = seccomp_init(SCMP_ACT_ERRNO(EACCES));
	if (sec_ctx == NULL) {
		logit("seccomp_init() failed. Continuing without seccomp\n");
		return;
	}

	seccomp_rule_add(sec_ctx, SCMP_ACT_ALLOW, SCMP_SYS(open), 0);
	seccomp_rule_add(sec_ctx, SCMP_ACT_ALLOW, SCMP_SYS(openat), 0);
	seccomp_rule_add(sec_ctx, SCMP_ACT_ALLOW, SCMP_SYS(close), 0);

	seccomp_rule_add(sec_ctx, SCMP_ACT_ALLOW, SCMP_SYS(read), 0);
	seccomp_rule_add(sec_ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 0);

	seccomp_rule_add(sec_ctx, SCMP_ACT_ALLOW, SCMP_SYS(sendto), 0);
	seccomp_rule_add(sec_ctx, SCMP_ACT_ALLOW, SCMP_SYS(recvfrom), 0);

	seccomp_rule_add(sec_ctx, SCMP_ACT_ALLOW, SCMP_SYS(splice), 0);
	seccomp_rule_add(sec_ctx, SCMP_ACT_ALLOW, SCMP_SYS(pipe2), 0);

	seccomp_rule_add(sec_ctx, SCMP_ACT_ALLOW, SCMP_SYS(chmod), 0);
	seccomp_rule_add(sec_ctx, SCMP_ACT_ALLOW, SCMP_SYS(chown), 0);
	seccomp_rule_add(sec_ctx, SCMP_ACT_ALLOW, SCMP_SYS(stat), 0);
	seccomp_rule_add(sec_ctx, SCMP_ACT_ALLOW, SCMP_SYS(fstat), 0);
	seccomp_rule_add(sec_ctx, SCMP_ACT_ALLOW, SCMP_SYS(fcntl), 0);

	seccomp_rule_add(sec_ctx, SCMP_ACT_ALLOW, SCMP_SYS(signalfd4), 0);
	seccomp_rule_add(sec_ctx, SCMP_ACT_ALLOW, SCMP_SYS(rt_sigprocmask), 0);
	seccomp_rule_add(sec_ctx, SCMP_ACT_ALLOW, SCMP_SYS(rt_sigaction), 0);
	seccomp_rule_add(sec_ctx, SCMP_ACT_ALLOW, SCMP_SYS(rt_sigreturn), 0);
	seccomp_rule_add(sec_ctx, SCMP_ACT_ALLOW, SCMP_SYS(pause), 0);

	seccomp_rule_add(sec_ctx, SCMP_ACT_ALLOW, SCMP_SYS(kill), 0);
	seccomp_rule_add(sec_ctx, SCMP_ACT_ALLOW, SCMP_SYS(wait4), 0);

	seccomp_rule_add(sec_ctx, SCMP_ACT_ALLOW, SCMP_SYS(socket), 0);
	seccomp_rule_add(sec_ctx, SCMP_ACT_ALLOW, SCMP_SYS(connect), 0);
	seccomp_rule_add(sec_ctx, SCMP_ACT_ALLOW, SCMP_SYS(bind), 0);
	seccomp_rule_add(sec_ctx, SCMP_ACT_ALLOW, SCMP_SYS(listen), 0);
	seccomp_rule_add(sec_ctx, SCMP_ACT_ALLOW, SCMP_SYS(accept4), 0);
	seccomp_rule_add(sec_ctx, SCMP_ACT_ALLOW, SCMP_SYS(getsockopt), 0);
	seccomp_rule_add(sec_ctx, SCMP_ACT_ALLOW, SCMP_SYS(setsockopt), 0);

	seccomp_rule_add(sec_ctx, SCMP_ACT_ALLOW, SCMP_SYS(epoll_create1), 0);
	seccomp_rule_add(sec_ctx, SCMP_ACT_ALLOW, SCMP_SYS(epoll_ctl), 0);
	seccomp_rule_add(sec_ctx, SCMP_ACT_ALLOW, SCMP_SYS(epoll_wait), 0);
	seccomp_rule_add(sec_ctx, SCMP_ACT_ALLOW, SCMP_SYS(select), 0);

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
