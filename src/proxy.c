/*
 * proxy.c - Core proxy functions
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

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <signal.h>
#include <sys/signalfd.h>
#include <fcntl.h>
#include <sys/epoll.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <netdb.h>
#include <netinet/in.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <pwd.h>
#include <grp.h>

#include <linux/if.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter_ipv6/ip6_tables.h>

#include <libac.h>

#include "sprotly.h"
#include "proxy.h"

#ifndef IP6T_SO_ORIGINAL_DST
#define IP6T_SO_ORIGINAL_DST	  80
#endif

#define MAX_EVENTS		 256
#define PIPE_SIZE	       16384

static const char * const event_type_str[] __maybe_unused = {
	"SPROTLY_LISTEN",
	"SPROTLY_PEER",
	"SPROTLY_PROXY",
	"SPROTLY_LOG_ROTATE"
};

enum event_type {
	SPROTLY_LISTEN = 0,
	SPROTLY_PEER,
	SPROTLY_PROXY,
	SPROTLY_LOG_ROTATE
};

enum proxy_conn_state {
	UNCONNECTED = 0,
	CONNECT_SENT,
	CONNECTED
};

struct buffer {
	int pipefds[2];
	ssize_t bytes;
};

struct conn {
	int type;
	int proxy_status;

	int fd;
	struct conn *other;
	struct buffer buf;

	char src_addr[INET6_ADDRSTRLEN];
	char dst_addr[INET6_ADDRSTRLEN];
};

static int epollfd;
extern int access_log_fd;
extern int error_log_fd;

static void reopen_logs(void)
{
	close(access_log_fd);
	access_log_fd = open(LOG_PATH"/"ACCESS_LOG, O_WRONLY | O_APPEND, 0666);

	close(error_log_fd);
	error_log_fd = open(LOG_PATH"/"ERROR_LOG, O_WRONLY | O_APPEND, 0666);
}

/*
 * Moves data from the pipe to the socket
 */
static bool write_to_sock(int dst_fd, struct buffer *buf)
{
	while (buf->bytes > 0) {
		ssize_t bytes = buf->bytes;
		ssize_t bs;

		if (bytes > PIPE_SIZE)
			bytes = PIPE_SIZE;

		bs = splice(buf->pipefds[0], NULL, dst_fd, NULL, bytes,
				SPLICE_F_MOVE | SPLICE_F_NONBLOCK);

		if (bs == 0)
			break;
		if (bs < 0) {
			if (errno == EAGAIN || errno == EWOULDBLOCK)
				break;
			return false;
		}
		buf->bytes -= bs;
	}

	return true;
}

/*
 * Moves data from the socket to the pipe
 */
static bool read_from_sock(int src_fd, struct buffer *buf)
{
	for (;;) {
		ssize_t bs = splice(src_fd, NULL, buf->pipefds[1], NULL,
				PIPE_SIZE, SPLICE_F_MOVE | SPLICE_F_NONBLOCK);

		if (bs > 0)
			buf->bytes += bs;
		if (bs == 0)
			return false;
		if (bs < 0) {
			if (errno == EAGAIN || errno == EWOULDBLOCK)
				return true;
			return false;
		}
	}

	return true;
}

static void close_conn(void *data, void *user_data __always_unused)
{
	struct conn *conn = (struct conn *)data;

	close(conn->buf.pipefds[0]);
	close(conn->buf.pipefds[1]);
	close(conn->fd);
}

static void set_conn_close(ac_slist_t **close_list, struct conn *conn)
{
	ac_slist_t *p = *close_list;

	while (p) {
		/* Don't add duplicate entries */
		if (p->data == conn)
			return;
		p = p->next;
	}

	ac_slist_preadd(close_list, conn->other);
	ac_slist_preadd(close_list, conn);
	epoll_ctl(epollfd, EPOLL_CTL_DEL, conn->fd, NULL);
	epoll_ctl(epollfd, EPOLL_CTL_DEL, conn->other->fd, NULL);
}

static void check_proxy_connect(struct conn *conn)
{
	char buf[PIPE_SIZE];
	ssize_t bytes_read;

	bytes_read = recv(conn->fd, &buf, PIPE_SIZE, 0);
	if (bytes_read == -1) {
		logerr("recv");
		return;
	}

	conn->other->proxy_status = CONNECTED;
}

static void send_proxy_connect(struct conn *conn)
{
	bool ipv6 = strchr(conn->other->dst_addr, ':') ? true : false;
	char buf[PIPE_SIZE + 1];
	ssize_t bytes_sent;
	int len;

	len = snprintf(buf, sizeof(buf), "CONNECT %s%s%s:443 HTTP/1.0\r\n\r\n",
				ipv6 ? "[" : "", conn->other->dst_addr,
				ipv6 ? "]" : "");
	bytes_sent = send(conn->fd, buf, len, 0);
	if (bytes_sent == -1) {
		logerr("send");
		return;
	}

	conn->other->proxy_status = CONNECT_SENT;
}

static struct conn *do_open_conn(const struct addrinfo *host,
				 struct conn *other)
{
	struct epoll_event ev;
	struct conn *conn;
	int ofd = socket(host->ai_family, SOCK_STREAM | SOCK_NONBLOCK, 0);
	int err;

	err = connect(ofd, host->ai_addr, host->ai_addrlen);
	if (err == -1 && errno != EINPROGRESS) {
		logerr("connect");
		return NULL;
	}

	conn = malloc(sizeof(struct conn));
	conn->type = SPROTLY_PROXY;
	conn->fd = ofd;

	/* These will always be nul terminated */
	strcpy(conn->dst_addr, other->dst_addr);
	strcpy(conn->src_addr, other->src_addr);

	err = pipe2(conn->buf.pipefds, O_NONBLOCK);
	if (err == -1) {
		free(conn);
		logerr("pipe2");
		return NULL;
	}
	conn->buf.bytes = 0;

	conn->other = other;
	other->other = conn;

	ev.events = EPOLLIN | EPOLLOUT | EPOLLET;
	ev.data.ptr = (void *)conn;
	epoll_ctl(epollfd, EPOLL_CTL_ADD, ofd, &ev);

	return other;
}

static void proxy_handshake(struct conn *conn)
{
	if (conn->other->proxy_status == UNCONNECTED)
		send_proxy_connect(conn);
	else if (conn->other->proxy_status == CONNECT_SENT)
		check_proxy_connect(conn);
}

static int do_accept(int lfd)
{
	int fd;
	int err;
	u16 src_port;
	bool ipv6;
	struct conn *conn;
	struct epoll_event ev;
	struct sockaddr_storage ss;
	socklen_t addrlen = sizeof(ss);

	fd = accept4(lfd, (struct sockaddr *)&ss, &addrlen, SOCK_NONBLOCK);
	if (fd == -1) {
		if (errno != EAGAIN && errno != EWOULDBLOCK)
			logerr("accept4");
		return -1;
	}
	conn = malloc(sizeof(struct conn));
	ac_net_inet_ntop(&ss, conn->src_addr, INET6_ADDRSTRLEN);
	src_port = ac_net_port_from_sa((struct sockaddr *)&ss);

	ipv6 = (ss.ss_family == AF_INET6) ? true : false;
	getsockopt(fd, ipv6 ? IPPROTO_IPV6 : IPPROTO_IP,
			ipv6 ? IP6T_SO_ORIGINAL_DST : SO_ORIGINAL_DST,
			(struct sockaddr *)&ss, &addrlen);

	conn->type = SPROTLY_PEER;
	conn->fd = fd;
	conn->other = NULL;
	conn->proxy_status = UNCONNECTED;

	err = pipe2(conn->buf.pipefds, O_NONBLOCK);
	if (err == -1) {
		free(conn);
		logerr("pipe2");
		return 0;
	};
	conn->buf.bytes = 0;

	ev.events = EPOLLIN | EPOLLOUT | EPOLLET;
	ev.data.ptr = (void *)conn;
	epoll_ctl(epollfd, EPOLL_CTL_ADD, fd, &ev);

	ac_net_inet_ntop(&ss, conn->dst_addr, INET6_ADDRSTRLEN);
	logit("Proxying %s%s%s:%hu->%s%s%s:%hu\n", ipv6 ? "[" : "",
			conn->src_addr, ipv6 ? "]" : "", src_port,
			ipv6 ? "[" : "", conn->dst_addr, ipv6 ? "]" : "",
			ac_net_port_from_sa((struct sockaddr *)&ss));

	return 0;
}

static void do_proxy(const struct addrinfo *proxy)
{
	for (;;) {
		int n;
		int nfds;
		ac_slist_t *close_list = NULL;
		struct epoll_event events[MAX_EVENTS];

		nfds = epoll_wait(epollfd, events, MAX_EVENTS, -1);
		for (n = 0; n < nfds; n++) {
			struct epoll_event *ev = &events[n];
			struct conn *conn = ev->data.ptr;
			struct conn *other = conn->other;

			if (conn->type == SPROTLY_LISTEN) {
				for (;;) {
					int ret;

					ret = do_accept(conn->fd);
					if (ret == -1)
						break;
				}
				continue;
			} else if (conn->type == SPROTLY_LOG_ROTATE) {
				ssize_t r __always_unused;
				struct signalfd_siginfo fdsi;

				r = read(conn->fd, &fdsi,
					 sizeof(struct signalfd_siginfo));

				reopen_logs();
				continue;
			}

			if (ev->events & (EPOLLERR | EPOLLHUP)) {
				set_conn_close(&close_list, conn);
				continue;
			}

			if (!other) {
				other = do_open_conn(proxy, conn);
				if (!other) {
					set_conn_close(&close_list, conn);
					continue;
				}
			}

			if (conn->type == SPROTLY_PEER &&
			    conn->proxy_status != CONNECTED) {
				read_from_sock(conn->fd, &conn->buf);
				continue;
			} else if (conn->type == SPROTLY_PROXY &&
				   other->proxy_status != CONNECTED) {
				proxy_handshake(conn);
				if (other->proxy_status != CONNECTED)
					continue;
			}

			if (ev->events & (EPOLLIN | EPOLLOUT)) {
				bool from;
				bool to;

				from = read_from_sock(conn->fd, &conn->buf);
				to = write_to_sock(other->fd, &conn->buf);
				if (!from || !to)
					set_conn_close(&close_list, conn);

				from = read_from_sock(other->fd, &other->buf);
				to = write_to_sock(conn->fd, &other->buf);
				if (!from || !to)
					set_conn_close(&close_list, conn);
			}
		}
		if (!close_list)
			continue;

		ac_slist_foreach(close_list, close_conn, NULL);
		ac_slist_destroy(&close_list, free);
	}
}

void init_proxy(const struct addrinfo *proxy)
{
	extern ac_slist_t *listen_fds;
	extern bool debug;
	extern uid_t euid;
	ac_slist_t *list = listen_fds;
	sigset_t mask;
	struct epoll_event ev;
	struct conn *conn;
	char *user = "sprotly";

	if (euid == 0) {
		struct passwd *pwd;
		int err;

		errno = 0;
		pwd = getpwnam(user);
		if (!pwd) {
			user = "nobody";
			pwd = getpwnam(user);
			if (!pwd) {
				if (errno == 0)
					logerr(NO_USER_MSG);
				else
					logerr("getpwnam");
				goto out_err;
			}
		}

		/* Drop root's supplimentary groups */
		err = setgroups(0, NULL);
		if (err) {
			logerr("setgroups");
			goto out_err;
		}

		/* Switch user */
		err = setgid(pwd->pw_gid);
		if (err) {
			logerr("setgid");
			goto out_err;
		}
		err = setuid(pwd->pw_uid);
		if (err) {
			logerr("setuid");
			goto out_err;
		}
		logit("Worker switched to user %s:%s (%d:%d)\n", user, user,
				pwd->pw_uid, pwd->pw_gid);
	}

	epollfd = epoll_create1(0);

	while (list) {
		conn = malloc(sizeof(struct conn));
		conn->type = SPROTLY_LISTEN;
		conn->fd = ((struct listen_fd *)list->data)->fd;
		conn->other = NULL;
		ev.events = EPOLLIN;
		ev.data.ptr = (void *)conn;
		epoll_ctl(epollfd, EPOLL_CTL_ADD, conn->fd, &ev);
		list = list->next;
	}

	if (!debug && euid == 0) {
		/* Setup SIGHUP signalfd handler for log file rotation */
		sigemptyset(&mask);
		sigaddset(&mask, SIGHUP);
		sigprocmask(SIG_BLOCK, &mask, NULL);

		conn = malloc(sizeof(struct conn));
		conn->type = SPROTLY_LOG_ROTATE;
		conn->fd = signalfd(-1, &mask, SFD_NONBLOCK);
		conn->other = NULL;
		ev.events = EPOLLIN;
		ev.data.ptr = (void *)conn;
		epoll_ctl(epollfd, EPOLL_CTL_ADD, conn->fd, &ev);
	}

	do_proxy(proxy);

out_err:
	sleep(5);	/* Don't go into a tight fork/exit loop */
	exit(EXIT_FAILURE);
}
