# Project settings
BINARY_NAME := obscura
MAIN_FILE := main.go

.PHONY: all build install deps clean tidy

# Default target
all: build

# Build the binary
build:
	go build -o $(BINARY_NAME) $(MAIN_FILE)

# Install the binary to $GOBIN
install:
	go install ./...

# Fetch and tidy dependencies
deps:
	go get golang.org/x/term@latest

tidy:
	go mod tidy

# Remove built binary
clean:
	rm -f $(BINARY_NAME)

