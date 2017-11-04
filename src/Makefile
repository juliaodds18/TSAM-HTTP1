CC = gcc
CPPFLAGS =
CFLAGS = -std=c11 -D_XOPEN_SOURCE=700 -O2 -Wall -Wextra -Wformat=2
CFLAGS += `pkg-config --cflags glib-2.0 openssl`
LDFLAGS =
LOADLIBES =
LDLIBS = `pkg-config --libs glib-2.0 openssl`


.DEFAULT: all
.PHONY: all
all: httpd

clean:
	rm -f *.o

distclean: clean
	rm -f httpd
