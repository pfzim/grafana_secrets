.PHONY: all clean linux windows darwin

BINARY_NAME=grafana_secrets_extractor
BUILD_DIR=bin

all: linux windows darwin

linux:
	@echo "Building Linux binaries..."
	GOOS=linux GOARCH=amd64 go build -o $(BUILD_DIR)/$(BINARY_NAME)_linux_amd64 .
	zip -j $(BUILD_DIR)/$(BINARY_NAME)_linux_amd64.zip $(BUILD_DIR)/$(BINARY_NAME)_linux_amd64
	
	GOOS=linux GOARCH=arm64 go build -o $(BUILD_DIR)/$(BINARY_NAME)_linux_arm64 .
	zip -j $(BUILD_DIR)/$(BINARY_NAME)_linux_arm64.zip $(BUILD_DIR)/$(BINARY_NAME)_linux_arm64

windows:
	@echo "Building Windows binaries..."
	GOOS=windows GOARCH=amd64 go build -o $(BUILD_DIR)/$(BINARY_NAME)_windows_amd64.exe .
	zip -j $(BUILD_DIR)/$(BINARY_NAME)_windows_amd64.zip $(BUILD_DIR)/$(BINARY_NAME)_windows_amd64.exe

darwin:
	@echo "Building Darwin binaries..."
	GOOS=darwin GOARCH=amd64 go build -o $(BUILD_DIR)/$(BINARY_NAME)_darwin_amd64 .
	zip -j $(BUILD_DIR)/$(BINARY_NAME)_darwin_amd64.zip $(BUILD_DIR)/$(BINARY_NAME)_darwin_amd64

clean:
	@echo "Cleaning build directory..."
	rm -rf $(BUILD_DIR)/*
