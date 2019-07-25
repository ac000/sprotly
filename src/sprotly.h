/* SPDX-License-Identifier: GPL-2.0 */

/*
 * sprotly.h
 *
 * Copyright (c) 2017		Securolytics, Inc.
 * 				Andrew Clayton <andrew.clayton@securolytics.io>
 *
 *		 2019		Andrew clayton <andrew@digital-domain.net>
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

#ifndef _SPROTLY_H_
#define _SPROTLY_H_

#define _GNU_SOURCE			/* vasprintf(3) */
#define _POSIX_C_SOURCE 200809L		/* dprintf(3) */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>
#include <time.h>
#include <errno.h>

#include <libac.h>

#define FQDN_MAX	255

#define LOG_PATH	"/var/log/sprotly"
#define ACCESS_LOG	"access_log"
#define ERROR_LOG	"error_log"

extern int access_log_fd;
extern int error_log_fd;

static inline void logit(const char *fmt, ...)
{
	int len;
	char *logbuf;
	va_list ap;

	va_start(ap, fmt);
	len = vasprintf(&logbuf, fmt, ap);
	if (len == -1) {
		va_end(ap);
		return;
	}
	va_end(ap);

	if (logbuf[0] == ' ') {
		/* continuation line */
		dprintf(access_log_fd, "%s", logbuf);
	} else {
		time_t secs = time(NULL);
		struct tm *tm = localtime(&secs);
		char tsbuf[32];

		strftime(tsbuf, sizeof(tsbuf), "%F %T %z", tm);
		dprintf(access_log_fd, "[%s] %d: %s", tsbuf, getpid(), logbuf);
	}

	free(logbuf);
}

static __maybe_unused void __logerr(const char *func, const char *what)
{
	time_t secs = time(NULL);
	struct tm *tm = localtime(&secs);
	char tsbuf[32];

	strftime(tsbuf, sizeof(tsbuf), "%F %T %z", tm);
	dprintf(error_log_fd, "[%s] %d %s %s%s%s\n", tsbuf, getpid(), func,
		what, (errno) ? ": " : "", (errno) ? strerror(errno) : "");
}

#define logerr(what)	__logerr(__func__, what)

#define err_exit(func) \
	do { \
		fprintf(stderr, "%s/%s%s%s\n", __func__, func, \
				(errno) ? ": " : "", \
				(errno) ? strerror(errno) : ""); \
		exit(EXIT_FAILURE); \
	} while (0)

#define NO_USER_MSG	"getpwnam: No suitable user, sprotly/nobody, found"

#endif /* _SPROTLY_H_ */
