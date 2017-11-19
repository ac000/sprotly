/*
 * sprotly.c - Main program, https transparent proxy
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
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/epoll.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <netdb.h>
#include <signal.h>
#include <getopt.h>
#include <errno.h>
#include <pwd.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/sysinfo.h>

#include <libac.h>

#include "sprotly.h"
#include "proxy.h"
#include "sprotly-seccomp.h"

/* What to set RLIMIT_NOFILE to */
#define NOFILE_LIMIT	65536

static char **rargv;

bool debug;
bool use_sni = true;
uid_t euid;

int access_log_fd;
int error_log_fd;

const char *access_log;
const char *error_log;

static const char *sprotly_pid_dir;
const char *sprotly_pid_file = "sprotly.pid";

ac_slist_t *listen_fds;

static volatile sig_atomic_t sprotly_terminate;
static volatile sig_atomic_t create_nr_new_workers;
static volatile sig_atomic_t log_rotation;

static void disp_usage(void)
{
	fprintf(stderr, "Usage: sprotly [-D] <-l [host]:port[,[host]:port,...]> <-p [proxy]:port> [-s] [-v] [-h]\n\n");

	fprintf(stderr, "  -D      - Run in debug mode. Log goes to terminal"
		        " and runs in the foreground.\n");
	fprintf(stderr, "  -l      - Listens on the optionally specified "
			"host/address(es) and port(s).\n             If no "
			"host is specified uses the unspecified address (::, "
			"0.0.0.0).\n             Listens on both IPv6 and "
			"IPv4.\n");
	fprintf(stderr, "  -p      - The optional host/address of the proxy "
			"and port to send requests\n             to. If the "
			"host is unspecified uses localhost. Will try IPv6 "
			"first\n             then IPv4.\n");
	fprintf(stderr, "  -s      - Disable TLS SNI extraction.\n");
	fprintf(stderr, "  -v      - Display the version.\n");
	fprintf(stderr, "  -h      - Display this text.\n\n");

	fprintf(stderr, "Example -\n\n");
	fprintf(stderr, "    sprotly -l localhost:3129 -p :9443\n");
}

static void set_proc_title(const char *title)
{
	size_t size = 0;
	int i;
	char *p;
	char *argv_last;
	extern char **environ;

	for (i = 0; environ[i]; i++)
		size += strlen(environ[i]) + 1;

	p = malloc(size);

	argv_last = rargv[0] + strlen(rargv[0]) + 1;

	for (i = 0; rargv[i]; i++) {
		if (argv_last == rargv[i])
			argv_last = rargv[i] + strlen(rargv[i]) + 1;
	}

	for (i = 0; environ[i]; i++) {
		if (argv_last == environ[i]) {
			size = strlen(environ[i]) + 1;
			argv_last = environ[i] + size;

			strncpy(p, environ[i], size);
			environ[i] = p;
			p += size;
		}
	}
	argv_last--;

	rargv[1] = NULL;
	strncpy(rargv[0], title, argv_last - rargv[0]);
}

static void unlink_pid(void)
{
	int dfd;

	if (euid != 0)
		return;

	dfd = open(sprotly_pid_dir, O_RDONLY | O_DIRECTORY);
	if (dfd == -1)
		return;

	unlinkat(dfd, sprotly_pid_file, 0);
	close(dfd);
}

static void write_pid(void)
{
	struct stat sb;
	FILE *fp;
	int dfd;
	int fd;
	int err;

	if (euid != 0)
		return;

	err = stat("/run", &sb);
	if (!err) {
		sprotly_pid_dir = "/run/sprotly";
	} else {
		err = stat("/var/run", &sb);
		if (err)
			return;
		sprotly_pid_dir = "/var/run/sprotly";
	}

	err = mkdir(sprotly_pid_dir, 0777);
	if (err && errno != EEXIST)
		return;

	dfd = open(sprotly_pid_dir, O_RDONLY | O_DIRECTORY);
	if (dfd == -1)
		return;

	fd = openat(dfd, sprotly_pid_file, O_WRONLY | O_CREAT | O_TRUNC, 0666);
	if (fd == -1)
		return;
	fp = fdopen(fd, "w");
	fprintf(fp, "%d\n", getpid());

	fclose(fp);
	close(dfd);
}

/*
 * Open log files, handling logfile rotation by sending a SIGHUP to
 * the worker processes notifying them to re-open their log files.
 */
static void open_logs(void)
{
	sigset_t hup;

	if (log_rotation) {
		close(access_log_fd);
		close(error_log_fd);
	}

	access_log_fd = open(access_log, O_WRONLY | O_CREAT | O_APPEND, 0666);
	error_log_fd = open(error_log, O_WRONLY | O_CREAT | O_APPEND, 0666);

	if (strncmp(access_log, "/proc", 5) != 0) {
		struct passwd *pwd = getpwnam("sprotly");
		int err __unused;

		if (!pwd) {
			pwd = getpwnam("nobody");
			if (!pwd) {
				errno = 0;
				err_exit(NO_USER_MSG);
			}
			logit("sprotly user not found, using 'nobody'\n");
		}

		chmod(LOG_PATH, 0700);
		err = chown(LOG_PATH, pwd->pw_uid, pwd->pw_gid);
		err = chown(access_log, pwd->pw_uid, pwd->pw_gid);
		err = chown(error_log, pwd->pw_uid, pwd->pw_gid);
	}

	if (!log_rotation)
		return;

	/*
	 * We don't want the master process receiving the HUP signal itself.
	 */
	sigemptyset(&hup);
	sigaddset(&hup, SIGHUP);
	sigprocmask(SIG_BLOCK, &hup, NULL);
	kill(0, SIGHUP);
	sigprocmask(SIG_UNBLOCK, &hup, NULL);

	log_rotation = 0;
}

static void sh_terminate(int signo __always_unused)
{
	sprotly_terminate = 1;
}

/*
 * Signal handler to handle child worker terminations.
 */
static void reaper(int signo __always_unused)
{
	int status;

	/*
	 * Make sure we catch multiple children terminating at the same
	 * time as we will only get one SIGCHLD while in this handler.
	 */
	while (waitpid(-1, &status, WNOHANG) > 0) {
		/*
		 * If a process dies, create a new one.
		 *
		 * However, don't create new processes if we get a
		 * SIGTERM or SIGKILL signal as that will stop the
		 * thing from being shutdown.
		 */
		if (WIFSIGNALED(status) &&
		    (WTERMSIG(status) != SIGTERM &&
		     WTERMSIG(status) != SIGKILL))
			create_nr_new_workers++;
	}
}

static void sh_log_rotation(int signo __always_unused)
{
	log_rotation = 1;
}

static bool split_host_port(const char *hostport, char *host, char *port)
{
	bool is_ipv6 = false;
	bool ret = true;
	int colons = 0;
	char *srv = strdup(hostport);

	while (*hostport) {
		if (*hostport == ':') {
			colons++;
			if (colons > 1) {
				is_ipv6 = true;
				break;
			}
		}
		hostport++;
	}

	if (!is_ipv6) {
		/* IPv4 or hostname */
		if (strchr(srv, ':')) {
			char *ptr = strchr(srv, ':');
			ptr++;
			snprintf(port, 6, "%s", ptr);
			ptr--;
			*ptr = '\0';
			strcpy(host, srv);
			goto out;
		}
	} else {
		/* IPv6 */
		if (strchr(srv, '[')) {
			char *ptr = strchr(srv, ']');
			ptr += 2; /* skip past ]: */
			snprintf(port, 6, "%s", ptr);
			ptr -= 2;
			*ptr = '\0';
			strcpy(host, srv + 1); /* +1 to skip past [ */
			goto out;
		}
	}

	ret = false;
out:
	free(srv);

	return ret;
}

/*
 * Returns 0 for success, -1 on failure
 */
static int try_proxy(struct addrinfo *proxy)
{
	int ret;
	int sockfd;
	int optval;
	fd_set fds;
	socklen_t optlen = sizeof(optval);
	struct timeval tv = { .tv_sec = 2, .tv_usec = 0 };

	sockfd = socket(proxy->ai_family, proxy->ai_socktype | SOCK_NONBLOCK,
			proxy->ai_protocol);

	/* Time connection attempts out after tv.tv_sec seconds */
	ret = connect(sockfd, proxy->ai_addr, proxy->ai_addrlen);
	if (ret == -1 && errno != EINPROGRESS)
		return ret;
	FD_ZERO(&fds);
	FD_SET(sockfd, &fds);
	ret = select(sockfd + 1, NULL, &fds, NULL, &tv);
	getsockopt(sockfd, SOL_SOCKET, SO_ERROR, &optval, &optlen);
	close(sockfd);

	if (ret == 0 || optval != 0)
		return -1;
	else
		return 0;
}

/*
 * Returns proxy addrinfo structure on success, NULL on failure
 */
static struct addrinfo *setup_proxy(const char *proxy_to)
{
	struct addrinfo *proxy;
	struct addrinfo hints;
	char host[NI_MAXHOST];
	char port[6];	/* 0..65535 + \0 */
	int err;

	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;

	if (proxy_to[0] == ':') {
		sprintf(host, "::1");
		sprintf(port, "%s", proxy_to + 1);
		getaddrinfo(host, port, &hints, &proxy);
		err = try_proxy(proxy);
		if (err) {
			freeaddrinfo(proxy);
			sprintf(host, "127.0.0.1");
			getaddrinfo(host, port, &hints, &proxy);
			err = try_proxy(proxy);
			if (err)
				freeaddrinfo(proxy);
		}
		if (!err)
			return proxy;
	} else {
		struct addrinfo *pp;

		if (!split_host_port(proxy_to, host, port))
			return NULL;

		getaddrinfo(host, port, &hints, &proxy);
		for (pp = proxy; pp != NULL; pp = pp->ai_next) {
			err = try_proxy(pp);
			if (!err)
				return pp;
		}
		freeaddrinfo(proxy);
	}

	return NULL;
}

/*
 * Returns 0 on success, -1 on failure
 */
static int bind_socket(const char *host, const char *port)
{
	int err;
	bool listener = false;
	struct addrinfo hints;
	struct addrinfo *res;
	struct addrinfo *resp;

	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;
	hints.ai_flags = AI_NUMERICSERV | AI_PASSIVE;

        err = getaddrinfo(host, port, &hints, &res);
	if (err)
		err_exit("getaddrinfo");
	for (resp = res; resp != NULL; resp = resp->ai_next) {
		int lfd;
		int optval = 1;
		bool ipv6 = (resp->ai_family == AF_INET6) ? true : false;
		socklen_t optlen = sizeof(optval);
		char addrp[INET6_ADDRSTRLEN];

		lfd = socket(resp->ai_family,
			     resp->ai_socktype | SOCK_NONBLOCK,
			     resp->ai_protocol);
		if (lfd == -1)
			err_exit("socket");

		setsockopt(lfd, SOL_SOCKET, SO_REUSEADDR, &optval, optlen);
		if (ipv6)
			setsockopt(lfd, IPPROTO_IPV6, IPV6_V6ONLY, &optval,
					optlen);

		err = bind(lfd, resp->ai_addr, resp->ai_addrlen);
		if (err)
			err_exit("bind");

		err = listen(lfd, 32);
		if (err)
			err_exit("listen");

		ac_net_inet_ntop(resp->ai_addr, addrp, INET6_ADDRSTRLEN);
		logit("Listening on %s%s%s:%s\n", ipv6 ? "[" : "", addrp,
				ipv6 ? "]" : "", port);

		ac_slist_add(&listen_fds, AC_LONG_TO_PTR(lfd));
		listener = true;
	}
	freeaddrinfo(res);

	if (listener)
		return 0;
	else
		return -1;
}

static void do_listen(const char *where)
{
	char host[NI_MAXHOST];
	char port[6];	/* 0..65535 + \0 */
	char **fields;
	char **l;

	fields = ac_str_split(where, ',', AC_STR_SPLIT_ALWAYS);
	for (l = fields; *l != NULL; l++) {
		/* Handle :port */
		if (*l[0] == ':') {
			bind_socket("::", *l + 1);
			bind_socket("0.0.0.0", *l + 1);
			return;
		}

		if (!split_host_port(*l, host, port)) {
			disp_usage();
			exit(EXIT_FAILURE);
		}
		bind_socket(host, port);
	}
	ac_str_freev(fields);
}

static void create_workers(int nr_workers, const struct addrinfo *proxy)
{
	int i;

	if (nr_workers == -1)
		nr_workers = get_nprocs();

	logit("Starting %d worker processes\n", nr_workers);
	for (i = 0; i < nr_workers; i++) {
		pid_t pid;

		pid = fork();
		if (pid == 0) {	/* child */
			set_proc_title("sprotly: worker");
			init_proxy(proxy);
		}
	}

	create_nr_new_workers = 0;
}

int main(int argc, char *argv[])
{
	int err;
	int optind;
	const char *listen_on = NULL;
	const char *proxy_to = NULL;
	char addrp[INET6_ADDRSTRLEN];
	struct addrinfo *proxy;
	struct sigaction action;

	while ((optind = getopt(argc, argv, "vhDsl:p:")) != -1) {
		switch (optind) {
		case 'D':
			debug = true;
			break;
		case 's':
			use_sni = false;
			break;
		case 'l':
			listen_on = optarg;
			break;
		case 'p':
			proxy_to = optarg;
			break;
		case 'v':
			fprintf(stdout, "%s\n", SPROTLY_VERSION + 1);
			exit(EXIT_SUCCESS);
		case 'h':
			disp_usage();
			exit(EXIT_SUCCESS);
		default:
			disp_usage();
			exit(EXIT_FAILURE);
		}
	}

	if (optind >= argc || !listen_on || !proxy_to) {
		disp_usage();
		exit(EXIT_FAILURE);
	}

	/* Used by set_proc_title() */
	rargv = argv;

	/* Don't terminate on -EPIPE */
	signal(SIGPIPE, SIG_IGN);

	/*
	 * Setup a signal handler for SIGTERM to terminate all the
	 * worker processes.
	 */
	sigemptyset(&action.sa_mask);
	action.sa_handler = sh_terminate;
	action.sa_flags = 0;
	sigaction(SIGTERM, &action, NULL);

	/*
	 * Setup a signal handler for SIGCHLD to handle worker
	 * process terminations.
	 */
	sigemptyset(&action.sa_mask);
	action.sa_handler = reaper;
	action.sa_flags = SA_RESTART;
	sigaction(SIGCHLD, &action, NULL);

	euid = geteuid();
	if (!debug && euid == 0) {
		access_log = LOG_PATH"/"ACCESS_LOG;
		error_log = LOG_PATH"/"ERROR_LOG;

		ac_fs_mkdir_p(LOG_PATH);
		/*
		 * Setup a signal handler for SIGHUP for logfile rotation,
		 * but not in debug mode as we're just using the console.
		 */
		sigemptyset(&action.sa_mask);
		action.sa_handler = sh_log_rotation;
		action.sa_flags = SA_RESTART;
		sigaction(SIGHUP, &action, NULL);
	} else {
		access_log = "/proc/self/fd/1";
		error_log = "/proc/self/fd/2";
		/* Ignore SIGHUP so we don't get killed by accident */
		signal(SIGHUP, SIG_IGN);
	}
	open_logs();

	logit("sprotly %s starting...\n", SPROTLY_VERSION + 1);
	if (!debug && euid != 0) {
		logit("Not running as root/uid 0, running in debug mode (-D)\n");
		debug = true;
	}

	/*
	 * Sprotly is quite file descriptor intensive, requiring 6 fd's
	 * per connection, i.e
	 *
	 *    1 - peer socket
	 *    2 - peer pipe r
	 *    3 - peer pipe w
	 *    4 - proxy socket
	 *    5 - proxy pipe r
	 *    6 - proxy pipe w
	 *
	 * So we need to try and set a reasonable RLIMIT_NOFILE value.
	 */
	if (euid == 0) {
		struct rlimit cur;

		getrlimit(RLIMIT_NOFILE, &cur);
		if (cur.rlim_max < NOFILE_LIMIT) {
			struct rlimit new = { .rlim_cur = NOFILE_LIMIT,
					      .rlim_max = NOFILE_LIMIT };

			err = setrlimit(RLIMIT_NOFILE, &new);
			if (err)
				logit("Failed to raise RLIMIT_NOFILE from "
						"%ld -> %ld\n", cur.rlim_max,
						new.rlim_max);
			else
				logit("Raised RLIMIT_NOFILE from %ld -> %ld\n",
						cur.rlim_max, new.rlim_max);
		}
	}

	do_listen(listen_on);
	proxy = setup_proxy(proxy_to);
	if (!proxy) {
		errno = 0;
		err_exit("setup_proxy: Error connecting to proxy\n");
	}

	ac_net_inet_ntop(proxy->ai_addr, addrp, INET6_ADDRSTRLEN);
	logit("Using proxy %s\n", addrp);

	if (!debug && euid == 0) {
		err = daemon(0, 0);
		if (err)
			err_exit("daemon");
	}

	if (use_sni)
		logit("Using the TLS SNI field for CONNECT requests\n");

	write_pid();
	init_seccomp();
	create_workers(-1, proxy);

	for (;;) {
		pause();

		if (create_nr_new_workers > 0)
			create_workers(create_nr_new_workers, proxy);
		if (log_rotation)
			open_logs();
		if (sprotly_terminate) {
			logit("Master got SIGTERM. Sending SIGTERM to workers and exiting\n");
			kill(0, SIGTERM);
			break;
		}
	}

	freeaddrinfo(proxy);
	ac_slist_destroy(&listen_fds, NULL);
	close(access_log_fd);
	close(error_log_fd);
	unlink_pid();

	exit(EXIT_SUCCESS);
}
