BINARY_NAME := authplex
BUILD_DIR := ./bin
VERSION ?= dev
COMMIT := $(shell git rev-parse --short HEAD 2>/dev/null || echo "none")
LDFLAGS := -ldflags "-X main.version=$(VERSION) -X main.commit=$(COMMIT)"

.PHONY: all build clean test test-unit test-func test-e2e lint coverage coverage-check docker

all: lint test-unit build

## Build
build:
	go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME) ./cmd/authplex

## Test
# Unit tests exclude infrastructure adapters (postgres, cache) that require external services.
# Those packages are covered by functional tests (make test-func).
test-unit:
	go test -v -race -count=1 -coverprofile=coverage-unit.out $$(go list ./... | grep -v '/adapter/postgres' | grep -v '/adapter/mssql' | grep -v '/adapter/sms' | grep -v '/adapter/email' | grep -v '/adapter/redis' | grep -v 'cmd/authplex')

test-func:
	go test -v -race -count=1 -tags=functional -coverprofile=coverage-func.out ./...

test-e2e:
	go test -v -count=1 -tags=e2e -timeout=300s ./e2e/...

test: test-unit

## Coverage
coverage: test-unit
	go tool cover -html=coverage-unit.out -o coverage.html
	@echo "Coverage report generated: coverage.html"

coverage-check: test-unit
	@./scripts/coverage.sh coverage-unit.out 80

## Lint
lint:
	golangci-lint run ./...

## Format
fmt:
	gofumpt -l -w .

## Docker
docker:
	docker build -t $(BINARY_NAME):$(VERSION) .

## Clean
clean:
	rm -rf $(BUILD_DIR) coverage-*.out coverage.html
