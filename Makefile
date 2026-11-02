.PHONY: all build build-web run dev dev-web test lint clean help init-config

BINARY_NAME=faradaiwire
CONFIG_FILE=config.yaml

help: ## Show available make targets
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-18s\033[0m %s\n", $$1, $$2}'

build-web: ## Build the React SPA frontend
	@if command -v npm >/dev/null 2>&1; then \
		echo "==> Building React SPA in web/..."; \
		(cd web && npm run build); \
	elif [ -d "web/dist" ]; then \
		echo "==> npm not found, using existing web/dist bundle..."; \
	else \
		echo "ERROR: npm is required to build web/dist" >&2; \
		exit 1; \
	fi

build: build-web ## Build the static gateway binary with embedded React SPA
	@echo "==> Building $(BINARY_NAME)..."
	go build -ldflags="-s -w" -o $(BINARY_NAME) ./cmd/faradaiwire

init-config: ## Initialize default configuration file if missing
	@if [ ! -f $(CONFIG_FILE) ]; then \
		echo "==> Initializing $(CONFIG_FILE) from config.example.yaml..."; \
		cp config.example.yaml $(CONFIG_FILE); \
	fi

run: build init-config ## Build and run gateway in standalone mode (Single-Command Start)
	@echo "==> Starting FaradAiWire on Ingress (:8090) and Admin (:8095)..."
	./$(BINARY_NAME) run --config $(CONFIG_FILE) --standalone

dev: init-config ## Run directly with go run (quick developer iteration)
	go run ./cmd/faradaiwire run --config $(CONFIG_FILE) --standalone

dev-web: ## Run the Vite development server with Hot Module Reloading (HMR)
	@echo "==> Starting Vite development server on :5173..."
	@cd web && npm run dev

test: ## Run all unit and integration tests across packages
	@echo "==> Running tests..."
	go test -race -v ./internal/... ./pkg/... ./cmd/...

lint: ## Run static code analysis and vet
	@echo "==> Running go vet..."
	go vet ./...

clean: ## Remove build artifacts and temporary logs
	rm -f $(BINARY_NAME)
	rm -rf logs/*.jsonl
