#
# Author: Markus Stenberg <fingon@iki.fi>
#
# Copyright (c) 2025 Markus Stenberg
#
# Created:       Sun Apr 13 08:23:25 2025 mstenber
# Last modified: Sat Apr 26 16:50:34 2025 mstenber
# Edit time:     7 min
#
#

GO_TEST_TARGET=./...

GENERATED=\
	proto/sssmemvault.pb.go \
	proto/sssmemvault_grpc.pb.go

BINARY=sssmemvault

.PHONY: all
all: ci

.PHONY: binaries
binaries: $(BINARY)

.PHONY: ci
ci: lint test $(BINARY)

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

$(BINARY): $(GENERATED)
	go build -o $@ ./cmd/$@

# Clean target (optional but good practice)
.PHONY: clean
clean:
	rm -f $(BINARY) $(GENERATED)
