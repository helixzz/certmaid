.PHONY: build test lint clean run install

APP_NAME := certmaid
BUILD_DIR := build
MAIN_PATH := ./cmd/certmaid

build:
	CGO_ENABLED=0 go build -ldflags="-s -w -X main.version=$(shell git describe --tags --always --dirty 2>/dev/null || echo 'dev')" -o $(BUILD_DIR)/$(APP_NAME) $(MAIN_PATH)

test:
	go test -race -count=1 -timeout=30s ./...

lint:
	golangci-lint run ./...

clean:
	rm -rf $(BUILD_DIR)

run: build
	$(BUILD_DIR)/$(APP_NAME) run --config config.example.yaml --dry-run

install: build
	install -m 755 $(BUILD_DIR)/$(APP_NAME) /usr/local/bin/$(APP_NAME)
