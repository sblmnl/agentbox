GO      ?= go
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
PREFIX  ?= /usr/local

.PHONY: all build test test-privileged fmt-check vet man-lint completions clean install

all: fmt-check vet build test

# CGO_ENABLED=0 is load-bearing, not tidiness: under the vm tier this same
# binary is bind-mounted into the box and run there as the egress forwarder,
# so it must not depend on the host's libc.
build:
	CGO_ENABLED=0 $(GO) build -trimpath ./cmd/agentbox

test:
	$(GO) test ./...

# The Layer-0 real-mount test needs root/CAP_SYS_ADMIN; it skips
# visibly elsewhere. CI for the container tier runs this target as root.
test-privileged:
	$(GO) test -run TestLayer0RealMounts ./internal/mask/ -v
	$(GO) test -run TestFilterRealMount ./internal/share/ -v

fmt-check:
	@out="$$(gofmt -l .)"; if [ -n "$$out" ]; then echo "gofmt needed:"; echo "$$out"; exit 1; fi

vet:
	$(GO) vet ./...

# Requires mandoc or groff.
man-lint:
	@for m in docs/man/agentbox.1 docs/man/agentbox.toml.5 docs/man/agentbox-security.7; do \
		if command -v mandoc >/dev/null; then mandoc -T lint -W warning $$m || exit 1; \
		elif command -v groff >/dev/null; then groff -man -t -z -ww $$m || exit 1; \
		else echo "skipping $$m (no mandoc/groff)"; fi; \
	done

completions: build
	mkdir -p completions
	./agentbox completion bash 2>/dev/null > completions/agentbox.bash
	./agentbox completion zsh  2>/dev/null > completions/_agentbox
	./agentbox completion fish 2>/dev/null > completions/agentbox.fish

install: build
	install -Dm755 agentbox $(DESTDIR)$(PREFIX)/bin/agentbox
	install -Dm644 docs/man/agentbox.1 $(DESTDIR)$(PREFIX)/share/man/man1/agentbox.1
	install -Dm644 docs/man/agentbox.toml.5 $(DESTDIR)$(PREFIX)/share/man/man5/agentbox.toml.5
	install -Dm644 docs/man/agentbox-security.7 $(DESTDIR)$(PREFIX)/share/man/man7/agentbox-security.7

clean:
	rm -rf agentbox dist completions
