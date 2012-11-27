PREFIX=/usr/local
DESTDIR=
LIBDIR=${PREFIX}/lib
INCDIR=${PREFIX}/include

CFLAGS+=-g -Wall -O2 -DDEBUG -fPIC
LIBS=-lev
AR=ar
AR_FLAGS=rc
RANLIB=ranlib

all: libevbuffsock

libevbuffsock: libevbuffsock.a test

%.o: %.c
	$(CC) -o $@ -c $< $(CFLAGS)

libevbuffsock.a: buffered_socket.o buffer.o
	$(AR) $(AR_FLAGS) $@ $^
	$(RANLIB) $@

test: test.o libevbuffsock.a
	$(CC) -o $@ $^ $(LIBS)

clean:
	rm -rf libbuffsock.a test *.o

.PHONY: install clean all

install:
	install -m 755 -d ${DESTDIR}${INCDIR}
	install -m 755 -d ${DESTDIR}${LIBDIR}
	install -m 755 libevbuffsock.a ${DESTDIR}${LIBDIR}/libevbuffsock.a
	install -m 755 evbuffsock.h ${DESTDIR}${INCDIR}/evbuffsock.h
