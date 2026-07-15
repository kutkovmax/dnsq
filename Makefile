CC ?= cc
CFLAGS ?= -O2 -std=c17 -Wall -Wextra -Wpedantic
CPPFLAGS ?= -I.

all: dnsq

dnsq: dnsq.c dns.c dns.h
	$(CC) $(CPPFLAGS) $(CFLAGS) dnsq.c dns.c -o $@

test: tests/test_dns
	./tests/test_dns

tests/test_dns: tests/test_dns.c dns.c dns.h
	$(CC) $(CPPFLAGS) $(CFLAGS) tests/test_dns.c dns.c -o $@

sanitizers:
	$(MAKE) CFLAGS='-O1 -g -std=c17 -Wall -Wextra -Wpedantic -fsanitize=address,undefined -fno-omit-frame-pointer' clean all test

clean:
	rm -f dnsq tests/test_dns

.PHONY: all test sanitizers clean
