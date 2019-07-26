/* SPDX-License-Identifier: GPL-2.0 */

/*
 * proxy.c - Core proxy functions
 *
 * Copyright (c) 2017		Securolytics, Inc.
 *				Andrew Clayton <andrew.clayton@securolytics.io>
 *
 *		 2019		Andrew Clayton <andrew@digital-domain.net>
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
#include <stdint.h>
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
#include <time.h>
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
#include "tls_sni.h"

#ifndef IP6T_SO_ORIGINAL_DST
#define IP6T_SO_ORIGINAL_DST	  80
#endif

#define MAX_EVENTS		 256
#define PIPE_SIZE	       16384

static const char * const event_type_str[] __maybe_unused = {
	"SPROTLY_LISTEN",
	"SPROTLY_PEER",
	"SPROTLY_PROXY",
	"SPROTLY_SIGNAL"
};

enum event_type {
	SPROTLY_LISTEN = 0,
	SPROTLY_PEER,
	SPROTLY_PROXY,
	SPROTLY_SIGNAL
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

	struct timespec start;

	int fd;
	struct conn *other;
	struct buffer buf;

	u16 src_port;
	u16 dst_port;
	char src_addr[INET6_ADDRSTRLEN];
	char dst_addr[INET6_ADDRSTRLEN];
	char dst_host[FQDN_MAX + 1];

	u64 bytes_tx;
	u64 bytes_rx;

	bool read_sni;
};

static int epollfd;
extern bool use_sni;
extern ac_slist_t *listen_fds;

static void reopen_logs(void)
{
	close(access_log_fd);
	access_log_fd = open(LOG_PATH"/"ACCESS_LOG, O_WRONLY | O_APPEND, 0666);

	close(error_log_fd);
	error_log_fd = open(LOG_PATH"/"ERROR_LOG, O_WRONLY | O_APPEND, 0666);
}

static void handle_signals(struct conn *conn)
{
	for (;;) {
		ssize_t r;
		struct signalfd_siginfo fdsi;

		r = read(conn->fd, &fdsi, sizeof(struct signalfd_siginfo));
		if (r == -1)
			break;

		if (fdsi.ssi_signo == SIGHUP)
			reopen_logs();
		if (fdsi.ssi_signo == SIGTERM) {
			logit("Worker got SIGTERM, exiting\n");
			close(conn->fd);
			close(access_log_fd);
			close(error_log_fd);
			close(epollfd);
			free(conn);
			ac_slist_destroy(&listen_fds, NULL);
			exit(EXIT_SUCCESS);
		}
	}
}

/*
 * Moves data from the pipe to the socket
 */
static bool write_to_sock(struct conn *dst, struct conn *src)
{
	while (src->buf.bytes > 0) {
		ssize_t bytes = src->buf.bytes;
		ssize_t bs;

		if (bytes > PIPE_SIZE)
			bytes = PIPE_SIZE;

		bs = splice(src->buf.pipefds[0], NULL, dst->fd, NULL, bytes,
				SPLICE_F_MOVE | SPLICE_F_NONBLOCK);

		if (bs == 0)
			break;
		if (bs < 0) {
			if (errno == EAGAIN || errno == EWOULDBLOCK)
				break;
			return false;
		}
		src->buf.bytes -= bs;
		if (dst->type == SPROTLY_PEER)
			dst->bytes_rx += bs;
	}

	return true;
}

/*
 * Moves data from the socket to the pipe
 */
static bool read_from_sock(struct conn *conn)
{
	for (;;) {
		ssize_t bs = splice(conn->fd, NULL, conn->buf.pipefds[1], NULL,
				PIPE_SIZE, SPLICE_F_MOVE | SPLICE_F_NONBLOCK);

		if (bs > 0)
			conn->buf.bytes += bs;
		if (bs == 0)
			return false;
		if (bs < 0) {
			if (errno == EAGAIN || errno == EWOULDBLOCK)
				break;
			return false;
		}
		if (conn->type == SPROTLY_PEER)
                        conn->bytes_tx += bs;
	}

	return true;
}

static void close_conn(void *data, void *user_data __always_unused)
{
	struct conn *conn = (struct conn *)data;
	struct timespec end;
	struct timespec delta;
	double et;
	bool ipv6;

	close(conn->buf.pipefds[0]);
	close(conn->buf.pipefds[1]);
	close(conn->fd);

	if (conn->type != SPROTLY_PEER)
		return;

	clock_gettime(CLOCK_MONOTONIC, &end);
	et = ac_time_tspec_diff(&delta, &end, &conn->start);

	ipv6 = strchr(conn->src_addr, ':');
	logit("Closed %s%s%s:%hu->%s%s%s%s:%hu, bytes tx/rx %" PRIu64 "/%"
			PRIu64 ", %.0fms\n", ipv6 ? "[" : "",
			conn->src_addr, ipv6 ? "]" : "",
			conn->src_port, conn->dst_host,
			(ipv6 || use_sni) ? "[" : "", conn->dst_addr,
			(ipv6 || use_sni) ? "]" : "", conn->dst_port,
			conn->bytes_tx, conn->bytes_rx, et*1000.0);
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

	if (conn->other) {
		ac_slist_preadd(close_list, conn->other);
		epoll_ctl(epollfd, EPOLL_CTL_DEL, conn->other->fd, NULL);
	}
	ac_slist_preadd(close_list, conn);
	epoll_ctl(epollfd, EPOLL_CTL_DEL, conn->fd, NULL);
}

static void check_proxy_connect(struct conn *conn)
{
	bool ipv6 = strchr(conn->other->src_addr, ':');
	char buf[PIPE_SIZE];
	ssize_t bytes_read;

	bytes_read = recv(conn->fd, &buf, PIPE_SIZE, 0);
	if (bytes_read == -1) {
		logerr("recv");
		return;
	}

	conn->other->proxy_status = CONNECTED;

	logit("Proxying %s%s%s:%hu->%s%s%s%s:%hu\n", ipv6 ? "[" : "",
			conn->other->src_addr, ipv6 ? "]" : "",
			conn->other->src_port, conn->other->dst_host,
			(ipv6 || use_sni) ? "[" : "", conn->other->dst_addr,
			(ipv6 || use_sni) ? "]" : "", conn->other->dst_port);
}

/*
 * Once connected to the proxy, send the correct CONNECT request through
 * with the destination IP address as retrieved from the tcp/ip stack.
 */
static void send_proxy_connect(struct conn *conn)
{
	bool ipv6 = strchr(conn->other->dst_addr, ':') &&
		!strlen(conn->other->dst_host);
	char buf[PIPE_SIZE + 1];
	ssize_t bytes_sent;
	int len;

	len = snprintf(buf, sizeof(buf), "CONNECT %s%s%s:443 HTTP/1.0\r\n\r\n",
				ipv6 ? "[" : "",
				strlen(conn->other->dst_host) ?
					conn->other->dst_host :
					conn->other->dst_addr,
				ipv6 ? "]" : "");
	bytes_sent = send(conn->fd, buf, len, 0);
	if (bytes_sent == -1) {
		logerr("send");
		return;
	}

	conn->other->proxy_status = CONNECT_SENT;
}

/*
 * Initiate a connection to the proxy.
 */
static struct conn *do_open_conn(const struct addrinfo *host,
				 struct conn *other)
{
	struct epoll_event ev;
	struct conn *conn;
	int ofd;
	int err;

	ofd = socket(host->ai_family, SOCK_STREAM | SOCK_NONBLOCK, 0);
	if (ofd == -1) {
		logerr("socket");
		return NULL;
	}
	err = connect(ofd, host->ai_addr, host->ai_addrlen);
	if (err == -1 && errno != EINPROGRESS) {
		logerr("connect");
		goto close_sock;
	}

	conn = malloc(sizeof(struct conn));
	if (!conn) {
		logerr("malloc");
		goto close_sock;
	}
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

close_sock:
	if (ofd > -1)
		close(ofd);
	return NULL;
}

/*
 * Handle the states of connecting to the proxy.
 */
static void proxy_handshake(struct conn *conn)
{
	if (conn->other->proxy_status == UNCONNECTED)
		send_proxy_connect(conn);
	else if (conn->other->proxy_status == CONNECT_SENT)
		check_proxy_connect(conn);
}

/*
 * After the initial 3way handshake, the first thing the client will
 * send is the 'Client Hello' message, try and extract the TLS SNI
 * field from this to use in the CONNECT request to the proxy before
 * actually forwarding the 'Client Hello' message etc...
 *
 * We use recv(2) with the MSG_PEEK flag set so the data will still be
 * there for splice(2).
 */
static void read_sni(struct conn *conn)
{
	ssize_t bytes;
	char buf[PIPE_SIZE];

	if (!use_sni)
		goto out_sni_read;

	bytes = recv(conn->fd, buf, sizeof(buf), MSG_PEEK);
	if (bytes == -1)
		return;
	parse_tls_header(buf, sizeof(buf), conn->dst_host);

out_sni_read:
	conn->read_sni = true;
}

/*
 * accept new connections from clients.
 */
static int do_accept(int lfd)
{
	int fd;
	int err;
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
	if (!conn) {
		close(fd);
		logerr("malloc");
		return 0;
	}
	clock_gettime(CLOCK_MONOTONIC, &conn->start);

	ac_net_inet_ntop(&ss, conn->src_addr, INET6_ADDRSTRLEN);
	conn->src_port = ac_net_port_from_sa((struct sockaddr *)&ss);

	/* Get the original destination IP address */
	ipv6 = ss.ss_family == AF_INET6;
	getsockopt(fd, ipv6 ? IPPROTO_IPV6 : IPPROTO_IP,
			ipv6 ? IP6T_SO_ORIGINAL_DST : SO_ORIGINAL_DST,
			(struct sockaddr *)&ss, &addrlen);
	ac_net_inet_ntop(&ss, conn->dst_addr, INET6_ADDRSTRLEN);
	conn->dst_port = ac_net_port_from_sa((struct sockaddr *)&ss);

	conn->type = SPROTLY_PEER;
	conn->fd = fd;
	conn->other = NULL;
	conn->proxy_status = UNCONNECTED;
	conn->read_sni = false;
	conn->dst_host[0] = '\0';
	conn->bytes_tx = 0;
	conn->bytes_rx = 0;

	err = pipe2(conn->buf.pipefds, O_NONBLOCK);
	if (err == -1) {
		close(conn->fd);
		free(conn);
		logerr("pipe2");
		return 0;
	};
	conn->buf.bytes = 0;

	ev.events = EPOLLIN | EPOLLOUT | EPOLLET;
	ev.data.ptr = (void *)conn;
	epoll_ctl(epollfd, EPOLL_CTL_ADD, fd, &ev);

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
			} else if (conn->type == SPROTLY_SIGNAL) {
				handle_signals(conn);
				continue;
			}

			if (ev->events & (EPOLLERR | EPOLLHUP)) {
				set_conn_close(&close_list, conn);
				continue;
			}

			if (conn->type == SPROTLY_PEER && !conn->read_sni) {
				read_sni(conn);
				if (!conn->read_sni)
					continue;
				other = do_open_conn(proxy, conn);
				if (!other) {
					set_conn_close(&close_list, conn);
					continue;
				}
				read_from_sock(conn);
				continue;
			} else if (conn->type == SPROTLY_PROXY &&
				   conn->other->read_sni &&
				   other->proxy_status != CONNECTED) {
				proxy_handshake(conn);
				if (other->proxy_status != CONNECTED)
					continue;
			}

			if (ev->events & (EPOLLIN | EPOLLOUT)) {
				bool from;
				bool to;

				from = read_from_sock(conn);
				to = write_to_sock(other, conn);
				if (!from || !to)
					set_conn_close(&close_list, conn);

				from = read_from_sock(other);
				to = write_to_sock(conn, other);
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

/*
 * Main proxy initialisation code.
 *
 * Whenever the master process forks a new worker, this is the function
 * that is called.
 */
void init_proxy(const struct addrinfo *proxy)
{
	extern bool debug;
	extern uid_t euid;
	ac_slist_t *list = listen_fds;
	sigset_t mask;
	struct epoll_event ev;
	struct conn *conn;
	char *user = "sprotly";

	/*
	 * If we are running as root, try switching to the 'sprotly'
	 * user, otherwise try the 'nobody' user.
	 */
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

	/* Add the listen socket(s) to epoll */
	while (list) {
		conn = malloc(sizeof(struct conn));
		conn->type = SPROTLY_LISTEN;
		conn->fd = AC_PTR_TO_LONG(list->data);
		conn->other = NULL;
		ev.events = EPOLLIN;
		ev.data.ptr = (void *)conn;
		epoll_ctl(epollfd, EPOLL_CTL_ADD, conn->fd, &ev);
		list = list->next;
	}

	/*
	 * Setup signalfd signal handling blocking the standard signal
	 * delivery for the signals we want handled by signalfd()
	 */
	sigemptyset(&mask);
	if (!debug && euid == 0) {
		/* SIGHUP for log file rotation */
		sigaddset(&mask, SIGHUP);
		sigprocmask(SIG_BLOCK, &mask, NULL);
	} else {
		/* Ignore SIGHUP so we don't get killed accidentally */
		signal(SIGHUP, SIG_IGN);
	}
	sigaddset(&mask, SIGTERM);
	sigprocmask(SIG_BLOCK, &mask, NULL);

	conn = malloc(sizeof(struct conn));
	conn->type = SPROTLY_SIGNAL;
	conn->fd = signalfd(-1, &mask, SFD_NONBLOCK);
	conn->other = NULL;
	ev.events = EPOLLIN;
	ev.data.ptr = (void *)conn;
	epoll_ctl(epollfd, EPOLL_CTL_ADD, conn->fd, &ev);

	do_proxy(proxy);

out_err:
	sleep(5);	/* Don't go into a tight fork/exit loop */
	exit(EXIT_FAILURE);
}
