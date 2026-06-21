VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)
BIN      := quorum

.PHONY: all build test vet fmt lint run clean docker-slim docker-full tidy

all: vet test build

build: ## Build the quorum binary into ./dist
	@mkdir -p dist
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o dist/$(BIN) ./cmd/quorum

test: ## Run unit + contract tests
	go test ./...

vet: ## go vet
	go vet ./...

fmt: ## Format the code
	gofmt -w .

tidy: ## Tidy modules
	go mod tidy

run: build ## Build then run (use ARGS="scan <target> ...")
	./dist/$(BIN) $(ARGS)

clean:
	rm -rf dist

docker-slim: ## Build quorum:slim (orchestrator only)
	docker build -f Dockerfile -t quorum:slim --build-arg VERSION=$(VERSION) .

docker-full: ## Build quorum:full (all scanners bundled)
	docker build -f Dockerfile.full -t quorum:full --build-arg VERSION=$(VERSION) .

help:
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
	  awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-14s\033[0m %s\n", $$1, $$2}'
