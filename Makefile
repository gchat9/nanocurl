# nanocurl -- teeniest-tiniest TLS 1.3 + HTTP/1.1 client.
#
#   make            build ./nanocurl
#   make test       build and run the whole test suite (see tests/)
#   make clean      remove built binaries

CC       ?= cc
CFLAGS   ?= -O2 -Wall -Wextra -std=c11
ASANFLAGS = -O1 -g -fsanitize=address,undefined -std=c11

TESTS_SRC = $(wildcard tests/test_*.c)
TESTS_BIN = $(patsubst tests/%.c,build/%,$(TESTS_SRC))

.PHONY: all test clean

all: nanocurl

nanocurl: nanocurl.c
	$(CC) $(CFLAGS) -o $@ $<

build:
	mkdir -p build

# Every test is built under AddressSanitizer + UBSan: several of these tests
# exist specifically to catch memory-safety regressions (see
# tests/test_large_records.c), so running them without a sanitizer would
# silently defeat the point.
build/%: tests/%.c nanocurl.c | build
	$(CC) $(ASANFLAGS) -o $@ $<

test: $(TESTS_BIN)
	@echo "== running test suite =="
	@status=0; \
	for t in $(TESTS_BIN); do \
		echo; \
		echo "--- $$t ---"; \
		./$$t || status=1; \
	done; \
	echo; \
	if [ $$status -eq 0 ]; then \
		echo "== all tests passed =="; \
	else \
		echo "== SOME TESTS FAILED =="; \
	fi; \
	exit $$status

clean:
	rm -f nanocurl
	rm -rf build
