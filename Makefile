.PHONY: build test lint clean install extension extension-dev extension-target extension-install

BINARY  := trivy-ls
EXT_DIR := vscode-trivy-ls
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X github.com/owenrumney/trivy-ls/internal/handler.Version=$(VERSION)

build:
	go build -ldflags "$(LDFLAGS)" -o bin/$(BINARY) ./cmd/trivy-ls

install:
	go install -ldflags "$(LDFLAGS)" ./cmd/trivy-ls

test:
	go test ./...

lint:
	golangci-lint run ./...

clean:
	rm -rf bin/
	rm -rf $(EXT_DIR)/bin/ $(EXT_DIR)/out/ $(EXT_DIR)/*.vsix

# Build the server and extension in place for F5 debugging.
extension-dev: build
	cd $(EXT_DIR) && npm install && npm run compile
	mkdir -p $(EXT_DIR)/bin
	cp bin/$(BINARY) $(EXT_DIR)/bin/$(BINARY)

# Build all platform .vsix files.
extension: test
	cd $(EXT_DIR) && npm install && npm run compile
	cd $(EXT_DIR) && node scripts/package.js

# Build a single platform .vsix (e.g. make extension-target VSCE_TARGET=darwin-arm64).
extension-target: test
	cd $(EXT_DIR) && npm install && npm run compile
	cd $(EXT_DIR) && VSCE_TARGET=$(VSCE_TARGET) node scripts/package.js

# Install the extension for the current platform into VS Code.
extension-install: build
	cd $(EXT_DIR) && npm install && npm run compile
	mkdir -p $(EXT_DIR)/bin
	cp bin/$(BINARY) $(EXT_DIR)/bin/$(BINARY)
	cd $(EXT_DIR) && npx vsce package
	code --install-extension $(EXT_DIR)/*.vsix --force
