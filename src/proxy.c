/* SPDX-License-Identifier: GPL-2.0 */

/*
 * proxy.c - Core proxy functions
 *
 * Copyright (c) 2017		Securolytics, Inc.
 *				Andrew Clayton <andrew.clayton@securolytics.io>
 *
 *		 2019, 2023	Andrew Clayton <andrew@digital-domain.net>
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
#include <pthread.h>

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

#define THREAD_STACK_SZ	  (8 * 1024)

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

enum eagain_state {
	EAGAIN_RD = 0,
	EAGAIN_WR = 1,

	/* Represents the bit pattern 11, i.e both the above bits set */
	EAGAIN_RDWR = 3
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

	int epfd;

	u16 src_port;
	u16 dst_port;
	char src_addr[INET6_ADDRSTRLEN];
	char dst_addr[INET6_ADDRSTRLEN];
	char dst_host[FQDN_MAX + 1];

	u64 bytes_tx;
	u64 bytes_rx;

	const struct addrinfo *proxy;

	u8 eagain_mask;

	bool done_sni;
};

static int epollfd;
extern bool use_sni;
extern ac_slist_t *listen_fds;
static ac_slist_t *listen_conns;

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
			ac_slist_destroy(&listen_conns, free);

			exit(EXIT_SUCCESS);
		}
	}
}

/*
 * Moves data from the pipe to the socket
 */
static bool write_to_sock(struct conn *dst, struct conn *src)
{
	AC_BYTE_BIT_SET(dst->eagain_mask, EAGAIN_WR);

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

		AC_BYTE_BIT_CLR(dst->eagain_mask, EAGAIN_WR);
	}

	return true;
}

/*
 * Moves data from the socket to the pipe
 */
static bool read_from_sock(struct conn *conn)
{
	AC_BYTE_BIT_SET(conn->eagain_mask, EAGAIN_RD);

	for (;;) {
		ssize_t bs = splice(conn->fd, NULL, conn->buf.pipefds[1], NULL,
				    PIPE_SIZE,
				    SPLICE_F_MOVE | SPLICE_F_NONBLOCK);

		if (bs == 0)
			return false;
		if (bs < 0) {
			if (errno == EAGAIN || errno == EWOULDBLOCK)
				break;
			return false;
		}
		conn->buf.bytes += bs;
		if (conn->type == SPROTLY_PEER)
                        conn->bytes_tx += bs;

		AC_BYTE_BIT_CLR(conn->eagain_mask, EAGAIN_RD);
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
		epoll_ctl(conn->epfd, EPOLL_CTL_DEL, conn->other->fd, NULL);
	}
	ac_slist_preadd(close_list, conn);
	epoll_ctl(conn->epfd, EPOLL_CTL_DEL, conn->fd, NULL);
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
static struct conn *do_open_conn(struct conn *conn)
{
	struct epoll_event ev;
	struct conn *proxy;
	int ofd;
	int err;

	ofd = socket(conn->proxy->ai_family, SOCK_STREAM | O_NONBLOCK, 0);
	if (ofd == -1) {
		logerr("socket");
		return NULL;
	}
	err = connect(ofd, conn->proxy->ai_addr, conn->proxy->ai_addrlen);
	if (err && errno != EINPROGRESS) {
		logerr("connect");
		goto close_sock;
	}

	proxy = malloc(sizeof(struct conn));
	if (!proxy) {
		logerr("malloc");
		goto close_sock;
	}
	proxy->type = SPROTLY_PROXY;
	proxy->fd = ofd;

	/* These will always be nul terminated */
	strcpy(proxy->dst_addr, conn->dst_addr);
	strcpy(proxy->src_addr, conn->src_addr);

	err = pipe2(proxy->buf.pipefds, O_NONBLOCK);
	if (err == -1) {
		free(proxy);
		logerr("pipe2");
		goto close_sock;
	}
	proxy->buf.bytes = 0;

	proxy->other = conn;
	conn->other = proxy;

	proxy->epfd = conn->epfd;

	proxy->eagain_mask = 0;

	ev.events = EPOLLIN | EPOLLOUT | EPOLLET;
	ev.data.ptr = (void *)proxy;
	epoll_ctl(proxy->epfd, EPOLL_CTL_ADD, ofd, &ev);

	return proxy;

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
	conn->done_sni = true;
}

static bool try_io(struct conn *conn)
{
	struct conn *other = conn->other;
	bool from;
	bool to;

	if (!other)
		return true;

	from = read_from_sock(conn);
	to = write_to_sock(other, conn);
	if (!from || !to)
		return false;

	from = read_from_sock(other);
	to = write_to_sock(conn, other);
	if (!from || !to)
		return false;

	return true;
}

static void set_epoll_timneout(const struct conn *conn, int *timeout)
{
	if (conn->eagain_mask == EAGAIN_RDWR &&
	    conn->other && conn->other->eagain_mask == EAGAIN_RDWR) {
		if (*timeout < 100)
			*timeout += 10;
		else if (*timeout < 1000)
			*timeout += 100;
		else if (*timeout < 2000)
			*timeout += 250;
		else if (*timeout < 5000)
			*timeout += 500;
		else
			*timeout = 5000;

		return;
	}

	*timeout = 10;
}

static void *handle_new_conn(void *arg)
{
	struct conn *conn = arg;
	struct epoll_event nev;
	struct epoll_event events[MAX_EVENTS];
	ac_slist_t *close_list = NULL;
	ac_slist_t *conns = NULL;
	int worker_epfd;
	int timeout = 10;
	int nfds;
	int n;
	int err;

	err = pipe2(conn->buf.pipefds, O_NONBLOCK);
	if (err) {
		close(conn->fd);
		free(conn);
		logerr("pipe2");
		return NULL;
	};
	conn->buf.bytes = 0;

	worker_epfd = epoll_create1(0);
	conn->epfd = worker_epfd;

	ac_slist_preadd(&conns, conn);

	nev.events = EPOLLIN | EPOLLOUT | EPOLLET;
	nev.data.ptr = (void *)conn;
	epoll_ctl(worker_epfd, EPOLL_CTL_ADD, conn->fd, &nev);

epoll_again:
	nfds = epoll_wait(worker_epfd, events, MAX_EVENTS, timeout);
	if (nfds == 0) {
		ac_slist_t *list = conns;

		while (list) {
			bool ok;

			ok = try_io(list->data);
			if (!ok)
				set_conn_close(&close_list, list->data);
			list = list->next;
		}
	}

	for (n = 0; n < nfds; n++) {
		struct epoll_event *ev = &events[n];
		struct conn *other;

		conn = ev->data.ptr;
		other = conn->other;

		if (ev->events & (EPOLLERR | EPOLLHUP)) {
			set_conn_close(&close_list, conn);
			continue;
		}

		if (conn->type == SPROTLY_PEER && !conn->done_sni) {
			read_sni(conn);
			if (!conn->done_sni)
				continue;
			other = do_open_conn(conn);
			if (!other) {
				set_conn_close(&close_list, conn);
				continue;
			}
			read_from_sock(conn);
			continue;
		} else if (conn->type == SPROTLY_PROXY &&
			   conn->other->done_sni &&
			   other->proxy_status != CONNECTED) {
			proxy_handshake(conn);
			if (other->proxy_status != CONNECTED)
				continue;

			ac_slist_preadd(&conns, conn);
		}

		if (ev->events & (EPOLLIN | EPOLLOUT)) {
			bool ok;

			ok = try_io(conn);
			if (!ok)
				set_conn_close(&close_list, conn);
		}
	}

	if (!close_list) {
		set_epoll_timneout(conn, &timeout);
		goto epoll_again;
	}

	ac_slist_destroy(&conns, NULL);

	ac_slist_foreach(close_list, close_conn, NULL);
	ac_slist_destroy(&close_list, free);

	close(worker_epfd);

	return NULL;
}

/*
 * accept new connections from clients.
 */
static void do_accept(int lfd, const struct addrinfo *proxy)
{
	int fd;
	bool ipv6;
	struct conn *conn;
	struct sockaddr_storage ss;
	socklen_t addrlen = sizeof(ss);
	pthread_t tid;
	pthread_attr_t attr;

accept_again:
	fd = accept4(lfd, (struct sockaddr *)&ss, &addrlen, SOCK_NONBLOCK);
	if (fd == -1) {
		if (errno != EAGAIN && errno != EWOULDBLOCK)
			logerr("accept4");
		return;
	}
	conn = malloc(sizeof(struct conn));
	if (!conn) {
		close(fd);
		logerr("malloc");
		return;
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
	conn->proxy = proxy;
	conn->done_sni = false;
	conn->dst_host[0] = '\0';
	conn->bytes_tx = 0;
	conn->bytes_rx = 0;
	conn->eagain_mask = 0;

	pthread_attr_init(&attr);
	pthread_attr_setstacksize(&attr, THREAD_STACK_SZ);
	pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
	pthread_create(&tid, &attr, handle_new_conn, conn);
	pthread_setname_np(tid, "sprotly: worker");
	pthread_attr_destroy(&attr);

	goto accept_again;
}

static void do_proxy(const struct addrinfo *proxy)
{
	int n;
	int nfds;
	struct epoll_event events[MAX_EVENTS];

epoll_again:
	nfds = epoll_wait(epollfd, events, MAX_EVENTS, -1);
	for (n = 0; n < nfds; n++) {
		struct epoll_event *ev = &events[n];
		struct conn *conn = ev->data.ptr;

		if (conn->type == SPROTLY_LISTEN) {
			do_accept(conn->fd, proxy);
			continue;
		} else if (conn->type == SPROTLY_SIGNAL) {
			handle_signals(conn);
			continue;
		}
	}
	goto epoll_again;
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
		ac_slist_preadd(&listen_conns, conn);
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

	ac_slist_preadd(&listen_conns, (void *)proxy);

	do_proxy(proxy);

out_err:
	sleep(5);	/* Don't go into a tight fork/exit loop */
	exit(EXIT_FAILURE);
}
