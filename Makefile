#
# Author: Markus Stenberg <fingon@iki.fi>
#
# Copyright (c) 2025 Markus Stenberg
#
# Created:       Sun Apr 13 08:23:25 2025 mstenber
# Last modified: Wed May 21 20:55:30 2025 mstenber
# Edit time:     21 min
#
#

GO_TEST_TARGET=./...

BINARY=sssmemvault

BINARIES=$(BINARY) \
	build/sssmemvault.linux-amd64 build/sssmemvault.darwin-arm64

GENERATED=\
	proto/sssmemvault.pb.go \
	proto/sssmemvault_grpc.pb.go

.PHONY: all
all: ci binaries

.PHONY: binaries
binaries: $(BINARIES)

build/sssmemvault.linux-amd64: $(wildcard *.go */*.go */*/*.go)
	@mkdir -p build
	GOOS=linux GOARCH=amd64 go build -o $@ ./cmd/sssmemvault

build/sssmemvault.darwin-arm64: $(wildcard *.go */*.go */*/*.go)
	@mkdir -p build
	GOOS=darwin GOARCH=arm64 go build -o $@ ./cmd/sssmemvault

.PHONY: ci
ci: lint test

.PHONY: generate
generate: $(GENERATED)

.PHONY: test
test: $(GENERATED)
	go test $(GO_TEST_TARGET)

# See https://golangci-lint.run/usage/linters/
.PHONY: lint
lint:
	golangci-lint run --fix  # Externally installed, e.g. brew

%.pb.go: %.proto
	protoc \
		--go_out=. --go_opt=paths=source_relative \
		$<
	grep -v "^//.*protoc[ -].*\sv" $@ > $@.tmp
	mv $@.tmp $@
	go tool goimports -w $@

%_grpc.pb.go: %.proto
	protoc \
		--go-grpc_out=. --go-grpc_opt=paths=source_relative \
		$<
	grep -v "^//.*protoc\s.*v" $@ > $@.tmp
	mv $@.tmp $@
	go tool goimports -w $@


$(BINARY): $(wildcard *.go */*.go */*/*.go)
	go test ./cmd/sssmemvault -count 1
	go build -o $@ ./cmd/$@

# Clean target (optional but good practice)
.PHONY: clean
clean:
	rm -f $(BINARIES) $(GENERATED)
