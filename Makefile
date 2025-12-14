.PHONY: help build test test-verbose test-coverage test-unit test-integration clean run lint fmt vet

# Variables
BINARY_NAME=protego
BUILD_DIR=bin
GO=go
GOFLAGS=-v
COVERAGE_DIR=coverage
CONFIG_FILE=testdata/sampleconfig/protego.yaml

# Colors for output
GREEN=\033[0;32m
YELLOW=\033[0;33m
RED=\033[0;31m
NC=\033[0m # No Color

help: ## Display this help message
	@echo "$(GREEN)Protego - Makefile commands:$(NC)"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  $(YELLOW)%-20s$(NC) %s\n", $$1, $$2}'

build: ## Build the binary
	@echo "$(GREEN)Building $(BINARY_NAME)...$(NC)"
	@mkdir -p $(BUILD_DIR)
	$(GO) build $(GOFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME) .
	@echo "$(GREEN)Build complete: $(BUILD_DIR)/$(BINARY_NAME)$(NC)"

test: ## Run all tests
	@echo "$(GREEN)Running all tests...$(NC)"
	$(GO) test -race -timeout 30s ./...

test-verbose: ## Run all tests with verbose output
	@echo "$(GREEN)Running all tests (verbose)...$(NC)"
	$(GO) test -v -race -timeout 30s ./...

test-coverage: ## Run tests with coverage report
	@echo "$(GREEN)Running tests with coverage...$(NC)"
	@mkdir -p $(COVERAGE_DIR)
	$(GO) test -race -coverprofile=$(COVERAGE_DIR)/coverage.out -covermode=atomic ./...
	$(GO) tool cover -html=$(COVERAGE_DIR)/coverage.out -o $(COVERAGE_DIR)/coverage.html
	@echo "$(GREEN)Coverage report generated: $(COVERAGE_DIR)/coverage.html$(NC)"
	$(GO) tool cover -func=$(COVERAGE_DIR)/coverage.out | grep total

test-unit: ## Run unit tests only
	@echo "$(GREEN)Running unit tests...$(NC)"
	$(GO) test -race -short -timeout 30s ./...

test-integration: ## Run integration tests only
	@echo "$(GREEN)Running integration tests...$(NC)"
	$(GO) test -race -run Integration -timeout 60s ./...

test-server: ## Run server package tests
	@echo "$(GREEN)Running server tests...$(NC)"
	$(GO) test -v -race ./pkg/server/...

test-dataprovider: ## Run dataprovider package tests
	@echo "$(GREEN)Running dataprovider tests...$(NC)"
	$(GO) test -v -race ./pkg/dataprovider/...

benchmark: ## Run benchmarks
	@echo "$(GREEN)Running benchmarks...$(NC)"
	$(GO) test -bench=. -benchmem ./...

clean: ## Clean build artifacts and coverage reports
	@echo "$(YELLOW)Cleaning build artifacts...$(NC)"
	@rm -rf $(BUILD_DIR)
	@rm -rf $(COVERAGE_DIR)
	@rm -f coverage.out
	@echo "$(GREEN)Clean complete$(NC)"

run: build ## Build and run the server
	@echo "$(GREEN)Starting $(BINARY_NAME)...$(NC)"
	./$(BUILD_DIR)/$(BINARY_NAME) -config $(CONFIG_FILE)

run-dev: ## Run the server in development mode (with dev build tag)
	@echo "$(GREEN)Starting $(BINARY_NAME) in development mode...$(NC)"
	$(GO) run -tags dev . -config $(CONFIG_FILE)

lint: ## Run golangci-lint
	@echo "$(GREEN)Running linter...$(NC)"
	@which golangci-lint > /dev/null || (echo "$(RED)golangci-lint not installed. Install from https://golangci-lint.run/$(NC)" && exit 1)
	golangci-lint run ./...

fmt: ## Format code with gofmt
	@echo "$(GREEN)Formatting code...$(NC)"
	$(GO) fmt ./...

vet: ## Run go vet
	@echo "$(GREEN)Running go vet...$(NC)"
	$(GO) vet ./...

tidy: ## Tidy go modules
	@echo "$(GREEN)Tidying go modules...$(NC)"
	$(GO) mod tidy

deps: ## Download dependencies
	@echo "$(GREEN)Downloading dependencies...$(NC)"
	$(GO) mod download

verify: fmt vet test ## Format, vet, and test the code
	@echo "$(GREEN)Verification complete!$(NC)"

ci: deps verify test-coverage ## Run CI pipeline (deps, verify, coverage)
	@echo "$(GREEN)CI pipeline complete!$(NC)"

docker-build: ## Build Docker image
	@echo "$(GREEN)Building Docker image...$(NC)"
	docker build -t $(BINARY_NAME):latest .

docker-run: docker-build ## Build and run Docker container
	@echo "$(GREEN)Running Docker container...$(NC)"
	docker run -p 8080:8080 -v $(PWD)/testdata:/app/testdata $(BINARY_NAME):latest

install: build ## Install the binary to $GOPATH/bin
	@echo "$(GREEN)Installing $(BINARY_NAME) to $(GOPATH)/bin...$(NC)"
	@cp $(BUILD_DIR)/$(BINARY_NAME) $(GOPATH)/bin/
	@echo "$(GREEN)Installation complete$(NC)"

generate-assets: ## Generate embedded assets (requires vfsgen)
	@echo "$(GREEN)Generating embedded assets...$(NC)"
	@which vfsgen > /dev/null || (echo "$(RED)vfsgen not installed. Run: go install github.com/shurcooL/vfsgen/cmd/vfsgen@latest$(NC)" && exit 1)
	$(GO) generate ./pkg/asset/

swagger: ## Generate swagger documentation
	@echo "$(GREEN)Generating swagger documentation...$(NC)"
	@which swag > /dev/null || (echo "$(RED)swag not installed. Run: go install github.com/swaggo/swag/cmd/swag@latest$(NC)" && exit 1)
	swag init -g pkg/server/handlers.go -o docs

.DEFAULT_GOAL := help

