PREFIX ?= /usr/local
DESTDIR ?=

.PHONY: build test vet check integration install package-deb

PACKAGE_VERSION ?= 0.0.0-dev
PACKAGE_ARCH ?= $(shell dpkg --print-architecture)

build:
	go build ./cmd/nestwg

test:
	go test ./...

vet:
	go vet ./...

check: test vet
	test -z "$$(gofmt -l .)"

integration:
	docker compose -f integration/docker-compose.yml up --build --abort-on-container-exit --exit-code-from lab

package-deb:
	mkdir -p dist
	CGO_ENABLED=0 GOOS=linux GOARCH="$(PACKAGE_ARCH)" go build -trimpath \
		-ldflags "-s -w -X main.version=$(PACKAGE_VERSION)" \
		-o "dist/nestwg-linux-$(PACKAGE_ARCH)" ./cmd/nestwg
	packaging/deb/build.sh "$(PACKAGE_VERSION)" "$(PACKAGE_ARCH)" \
		"dist/nestwg-linux-$(PACKAGE_ARCH)" dist

install:
	test -x nestwg
	install -Dm755 nestwg "$(DESTDIR)$(PREFIX)/bin/nestwg"
	install -Dm644 docs/nestwg.1 "$(DESTDIR)$(PREFIX)/share/man/man1/nestwg.1"
	install -Dm644 completions/nestwg.bash "$(DESTDIR)$(PREFIX)/share/bash-completion/completions/nestwg"
	install -Dm644 completions/_nestwg "$(DESTDIR)$(PREFIX)/share/zsh/site-functions/_nestwg"
	install -Dm644 completions/nestwg.fish "$(DESTDIR)$(PREFIX)/share/fish/vendor_completions.d/nestwg.fish"
