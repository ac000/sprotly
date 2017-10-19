SPROTLY_VERSION = $(shell git describe --dirty --always)

CC	= gcc
CFLAGS	= -Wall -Wextra -std=c99 -O2 -g -Wp,-D_FORTIFY_SOURCE=2 -D_FILE_OFFSET_BITS=64 -fexceptions -fstack-protector --param=ssp-buffer-size=4 -fPIC -DSPROTLY_VERSION='"${SPROTLY_VERSION}"'
LDFLAGS	= -Wl,-z,relro -Wl,-z,now -pie
LIBS	= -lac
INCS	=

GLIBC_MAJOR     := $(shell ldd --version | grep -Eo '[0-9]+\.[0-9]+' | \
                           cut -d . -f 1)
GLIBC_MINOR	:= $(shell ldd --version | grep -Eo '[0-9]+\.[0-9]+' | \
                           cut -d . -f 2)
GLIBC_VER_2_18+	:= $(shell test $(GLIBC_MAJOR) -ge 2 && \
                           test $(GLIBC_MINOR) -ge 17 && \
                           echo 1)

ifneq "$(GLIBC_VER_2_18+)" "1"
# clock_* functions need linking against -lrt in glibc < 2.17
LIBS += -lrt
endif

ifeq (${SPROTLY_SECCOMP}, 0)
# Don't build with seccomp support
CFLAGS  +=
else ifeq ($(shell pkg-config --exists libseccomp && echo 1), 1)
LIBS	+= -lseccomp
CFLAGS	+= -D_HAVE_LIBSECCOMP
endif

sources =	$(wildcard *.c)
objects =	$(sources:.c=.o)

sprotly: $(objects)
	@echo -e "  LNK\t$@"
	@$(CC) $(LDFLAGS) -o $@ $(objects) $(LIBS)

$(objects): %.o: %.c
	@echo -e "  CC\t$@"
	@$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f sprotly *.o
