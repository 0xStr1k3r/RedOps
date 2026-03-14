.PHONY: build test vet run-api lint clean sync-web install
BIN=bin
PREFIX=/usr/local
DESTDIR=
VERSION=$(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS=-s -w -X main.version=$(VERSION)

build: sync-web
	mkdir -p $(BIN)
	go build -ldflags "$(LDFLAGS)" -o $(BIN)/redops-api ./cmd/server
	go build -ldflags "$(LDFLAGS)" -o $(BIN)/redops ./cmd/cli
	go build -ldflags "$(LDFLAGS)" -o $(BIN)/redops-worker ./cmd/worker

# The GUI source of truth is web/dist; the API embeds a generated copy.
sync-web:
	mkdir -p internal/api/webdist
	cp web/dist/index.html web/dist/app.js web/dist/styles.css internal/api/webdist/

test:
	go test ./...

vet:
	go vet ./...

run-api: sync-web
	REDOPS_JWT_SECRET=$${REDOPS_JWT_SECRET:-dev-secret-32-bytes-minimum-xxxxxxxx} REDOPS_DB=$${REDOPS_DB:-redops.db} go run ./cmd/server

# Single-binary install: the `redops` CLI manages everything
# (serve/worker/project/recon/enum/findings/paths/graph/report/...).
install: build
	install -d $(DESTDIR)$(PREFIX)/bin
	install -m 0755 $(BIN)/redops $(DESTDIR)$(PREFIX)/bin/redops

clean:
	rm -rf $(BIN) redops.db internal/api/webdist
