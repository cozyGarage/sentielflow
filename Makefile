# Makefile for SentinelFlow

BINARY_NAME=sentinelflow
DOCKER_IMAGE=sentinelflow/sentinelflow:latest

.PHONY: all build test bench clean docker-build run demo

all: test build

build:
	@echo "Building SentinelFlow..."
	go build -ldflags "-X main.version=1.0.0 -X main.commit=dev -X main.date=unknown" -o $(BINARY_NAME) ./cmd/sentinelflow

test:
	@echo "Running unit tests..."
	go test -v ./...

integration:
	@echo "Running integration tests..."
	go test -tags=integration -v ./test/...

bench:
	@echo "Running benchmarks..."
	go test -bench=. -benchmem -v ./internal/scanner/... ./internal/reporter/...

docker-build:
	@echo "Building Docker image..."
	docker build -t $(DOCKER_IMAGE) .

clean:
	@echo "Cleaning up..."
	@if [ -f $(BINARY_NAME) ]; then rm $(BINARY_NAME); fi
	@if [ -f sentinelflow.exe ]; then rm sentinelflow.exe; fi
	@go clean

run: build
	./$(BINARY_NAME) --help

demo: build
	@chmod +x ./scripts/demo.sh
	./scripts/demo.sh

scan-self: build
	./$(BINARY_NAME) scan --all .

lint:
	@echo "Running lint (requires golangci-lint)..."
	golangci-lint run
