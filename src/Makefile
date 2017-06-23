SPROTLY_VERSION = $(shell git describe --dirty --always)

CC	= gcc
CFLAGS	= -Wall -Wextra -std=c99 -O2 -g -Wp,-D_FORTIFY_SOURCE=2 -D_FILE_OFFSET_BITS=64 -fexceptions -fstack-protector --param=ssp-buffer-size=4 -fPIC -DSPROTLY_VERSION='"${SPROTLY_VERSION}"'
LDFLAGS	= -Wl,-z,relro -Wl,-z,now -pie
LIBS	= -lac
INCS	=

objects = sprotly.o proxy.o

sprotly: $(objects)
	@echo -e "  LNK\t$@"
	@$(CC) $(LDFLAGS) -o $@ $(objects) ${LIBS}

sprotly.o: sprotly.c
	@echo -e "  CC\t$@"
	@$(CC) $(CFLAGS) -c -o $@ $<

proxy.o: proxy.c
	@echo -e "  CC\t$@"
	@$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f sprotly *.o
