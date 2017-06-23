/*
 * sprotly.h
 *
 * Copyright (c) 2017		Securolytics, Inc.
 * 				Andrew Clayton <andrew.clayton@securolytics.io>
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>

#define LOG_PATH	"/var/log/sprotly"
#define ACCESS_LOG	"access_log"
#define ERROR_LOG	"error_log"

#define logit(fmt, ...) \
	do { \
		int len; \
		time_t secs = time(NULL); \
		struct tm *tm = localtime(&secs); \
		char tsbuf[32]; \
		char logbuf[256]; \
		ssize_t bytes_wrote __always_unused; \
		\
		strftime(tsbuf, sizeof(tsbuf), "%F %T %z", tm); \
		len = snprintf(logbuf, sizeof(logbuf), "[%s] %d: " fmt, \
			       tsbuf, getpid(), ##__VA_ARGS__); \
		bytes_wrote = write(access_log_fd, logbuf, len); \
	} while (0)

#define logerr(what) \
	do { \
		int len; \
		time_t secs = time(NULL); \
		struct tm *tm = localtime(&secs); \
		char tsbuf[32]; \
		char logbuf[256]; \
		ssize_t bytes_wrote __always_unused; \
		\
		strftime(tsbuf, sizeof(tsbuf), "%F %T %z", tm); \
		len = snprintf(logbuf, sizeof(logbuf), "[%s] %d %s %s%s%s\n", \
			       tsbuf, getpid(), __func__, what, \
			       (errno) ? ": " : "", \
			       (errno) ? strerror(errno) : ""); \
		bytes_wrote = write(error_log_fd, logbuf, len); \
	} while (0)

#define err_exit(func) \
	do { \
		fprintf(stderr, "%s/%s%s%s\n", __func__, func, \
				(errno) ? ": " : "", \
				(errno) ? strerror(errno) : ""); \
		exit(EXIT_FAILURE); \
	} while (0)

#define NO_USER_MSG	"getpwnam: No suitable user, sprotly/nobody, found"

#endif /* _SPROTLY_H_ */
