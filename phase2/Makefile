CC = gcc
CFLAGS = -Wall -Wextra -O2
LDLIBS = -lpcap

interceptor: interceptor.c
	$(CC) $(CFLAGS) -o $@ $< $(LDLIBS)

clean:
	rm -f interceptor
