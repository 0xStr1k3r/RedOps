.PHONY: build test vet run-api lint clean
BIN=bin

build:
	mkdir -p $(BIN)
	go build -o $(BIN)/redops-api ./cmd/server
	go build -o $(BIN)/redops ./cmd/cli
	go build -o $(BIN)/redops-worker ./cmd/worker

test:
	go test ./...

vet:
	go vet ./...

run-api:
	REDOPS_JWT_SECRET=$${REDOPS_JWT_SECRET:-dev-secret-32-bytes-minimum-xxxxxxxx} REDOPS_DB=$${REDOPS_DB:-redops.db} go run ./cmd/server

clean:
	rm -rf $(BIN) redops.db
