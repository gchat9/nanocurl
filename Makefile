# nanocurl -- teeniest-tiniest TLS 1.3 + HTTP/1.1 client.
#
#   make                 build ./nanocurl and ./nanocurl-verify
#   CC="diet gcc" make   same, but statically linked against dietlibc
#   make test            build and run the whole test suite

CC       ?= cc
CFLAGS   ?= -O2 -Wall -Wextra -std=c11

# tests are not expected to work under diet, so we use HOSTCC there
HOSTCC   ?= cc
ASANFLAGS = -O1 -g -fsanitize=address,undefined -std=c11

TESTS_SRC = $(wildcard tests/test_*.c)
TESTS_BIN = $(patsubst tests/%.c,build/%,$(TESTS_SRC))

.PHONY: all test clean

all: nanocurl nanocurl-verify

nanocurl: nanocurl.c strlite.h crypto/sha256.h crypto/handshake_crypto.h
	$(CC) $(CFLAGS) -o $@ nanocurl.c

nanocurl-verify: nanocurl-verify.c crypto/*.h
	$(CC) $(CFLAGS) -o $@ nanocurl-verify.c

build:
	mkdir -p build

# Every test is built under AddressSanitizer + UBSan with the host
# compiler -- several of these tests exist specifically to catch
# memory-safety regressions, so running them without a sanitizer would
# silently defeat the point.
build/%: tests/%.c nanocurl.c | build
	$(HOSTCC) $(ASANFLAGS) -o $@ $<

test: $(TESTS_BIN)
	@echo "== running test suite =="
	@status=0; \
	for t in $(TESTS_BIN); do \
		echo; \
		echo "--- $$t ---"; \
		( cd tests; ../$$t ) || status=1; \
	done; \
	echo; \
	if [ $$status -eq 0 ]; then \
		echo "== all tests passed =="; \
	else \
		echo "== SOME TESTS FAILED =="; \
	fi; \
	exit $$status

clean:
	rm -f nanocurl nanocurl-verify
	rm -rf build
