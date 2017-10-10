## Overview

What's in a name? *sprotly*; *proxy* -> *proxly*, *x* -> *t* for transparent
and *s* for splice, as it uses the Linux *splice(2)* system call.

sprotly is a tool to sit in front of a proxy such as squid and forward https
client requests to the proxy converting them into *CONNECT*'s.

This would be used for cases where you want to be able to perform some action
on https requests based purely on destination IP address within squid and
don't want them run through SSLBump.

This is done by using an iptables rule to redirect port 443 traffic to a
port that sprotly is listening on e.g

    # ip6tables -t nat -A PREROUTING -p tcp -m tcp --dport 443 -j REDIRECT --to-ports 3129
    # iptables -t nat -A PREROUTING -p tcp -m tcp --dport 443 -j REDIRECT --to-ports 3129
    # sprotly -S -l localhost:3129 -p :9443

Thus any traffic destined for port 443 is redirected to port 3129 where
sprotly turns the standard requests into CONNECT's as squid would be
expecting them for https requests. The corresponding squid config for this
would be

    http_port 9443

It then connects to squid on port 9443 (it will try IPv6 first then IPv4)
on localhost (by not specifying a host) and sends the CONNECT request, once
it gets the OK from squid it then just shuffles packets back and forth
between the client and squid.


## Building

The only hard requirement is libac. On a rpm based system something like the
following should work

    $ git clone https://github.com/ac000/libac
    $ cd libac
    $ cp libac.spec ~/rpmbuild/SPECS
    $ git archive --format=tar --prefix=libac-$(grep ^Version libac.spec | cut -f 2)/ -o ~/rpmbuild/SOURCES/libac-$(grep ^Version libac.spec | cut -f 2).tar HEAD
    $ rpmbuild -bb ~/rpmbuild/SPECS/libac.spec
    $ sudo dnf install ~/rpmbuild/RPMS/x86_64/libac-<VERSION>-?.<DIST>.x86_64.rpm

You can create a suitable rpmbuild tree with

    $ mkdir -p ~/rpmbuild/{BUILD,RPMS,SOURCES,SPECS,SRPMS}

sprotly can optionally include support for seccomp via libseccomp if you have
it installed, e.g on Red Hat based distros this would be the

    libseccomp
    libseccomp-devel

packages.

This can be disabled at build time by setting the SPROTLY\_SECCOMP shell
environment variable to 0. e.g

    $ SPROTLY_SECCOMP=0 make

For sprotly

    $ git clone https://github.com/ac000/sprotly
    $ cd src
    $ make
    $ sudo install -Dp 0755 sprotly /usr/local/sbin/


## How to use

sprotly has no configuration file and has only a few options

    $ ./sprotly -h
    Usage: sprotly [-D] <-l [host]:port[,...]> <-p [proxy]:port> [-s] [-v] [-h]

      -D      - Run in debug mode. Log goes to terminal and runs in the
                 foreground.
      -l      - Listens on the optionally specified host/address(es) and
                 port(s). If no host is specified uses the unspecified address
                 (::, 0.0.0.0). Listens on both IPv6 and IPv4.
      -p      - The optional host/address of the proxy and port to send
                 requests to. If the host is unspecified uses localhost. Will
                 try IPv6 first then IPv4.
      -s      - Disable TLS SNI extraction.
      -v      - Display the version.
      -h      - Display this text.

    Example -

        sprotly -l localhost:3129 -p :9443

*-l* and *-p* are the only required options. And the example shown is generally
how you'd want to run it.

-l can take a comma separated list of [host]:port pairs.

This will tell sprotly to listen on port *3129* on *::1* and *127.0.0.1* for
client requests which have been redirected by the above ip{6}tables rules.

It will then send the *CONNECT* requests to the proxy running on *::1* or
*127.0.0.1* on port *9443*.

By default sprotly will try to extract the requested hostname as given in the
TLS SNI field from the 'Client Hello' message and use this in the *CONNECT*
requests. If there isn't one it will fall back to using the IP address as
retrieved from the network stack.

-s is used to tell sprotly not to do this and just use the IP address.


## Architecture

sprotly uses a multiprocess non-blocking I/O event driven model.

When started, sprotly will fork a worker process for each cpu in the system.
These *worker* processes handle all the network I/O. They use *epoll(7)* for
a scalable I/O event notification facility.

For the actual sending/receiving of data to/from client/proxy it uses the
*splice(2)* system call which has the potential to allow for zero copy I/O.

This in general should make sprotly pretty efficient. However it does make
sprotly somewhat file descriptor hungry requiring *six* fd's per connection.
i.e

    1 - peer socket
    2 - peer pipe read end
    3 - peer pipe write end
    4 - proxy socket
    5 - proxy pipe read end
    6 - proxy pipe write end

however on modern 64bit systems with plenty of RAM this shouldn't really be an
issue, hence at startup sprotly will attempt to increase RLIMIT\_NOFILE to
*65536*. This limit is per-process and should allow for 10,000+ connections
per worker.

When run as root, the worker processes will change to run as the *sprotly*
user. Also sprotly will write to two log files; */var/log/sprotly/access_log*
and */var/log/sprotly/error_log*.

If the sprotly user doesn't exist, then it will try using the 'nobody' user.

You can create a *sprotly* user like

    # useradd -r -d / -s /sbin/nologin sprotly

Also by default sprotly will *daemon(3)ize* itself. When run in the foreground
*(-D)* sprotly simply logs to the terminal.

sprotly can also optionally do syscall filtering with seccomp(2) via
libseccomp if you have it installed.


## License

sprotly is licensed under the GNU General Public License version 2. See
*COPYING*.


## Contributing

Patches and/or pull requests should be emailed to the project maintainer

    Andrew Clayton <andrew.clayton@securolytics.io>

preferably using *git-send-email(1)* and *git-request-pull(1)*

Code should follow the coding style as outlined in *CodingStyle*.

Also, code should be signed-off. This means adding a line that says

    Signed-off-by: Name <email>

at the end of each commit, indicating that you wrote the code and have the
right to pass it on as an open source patch.

See: <http://developercertificate.org/>
