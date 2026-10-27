VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)
PLATFORMS := darwin/arm64 darwin/amd64 linux/arm64 linux/amd64

.PHONY: build install test check dist clean

build:
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o bin/smem ./cmd/smem

install:
	CGO_ENABLED=0 go install -trimpath -ldflags "$(LDFLAGS)" ./cmd/smem

test:
	go vet ./...
	go test -race ./...

# What CI runs on every PR, apart from fuzzing and the security scans.
check:
	@test -z "$$(gofmt -l .)" || { gofmt -l .; echo "run gofmt -w ."; exit 1; }
	go mod tidy && git diff --exit-code go.mod go.sum
	go vet ./...
	golangci-lint run ./...
	go test -race -count=1 -shuffle=on ./...

# Static binaries for every platform, without a release.
dist:
	@for p in $(PLATFORMS); do \
		os=$${p%/*}; arch=$${p#*/}; \
		echo "dist/smem_$${os}_$${arch}"; \
		CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch go build -trimpath -ldflags "$(LDFLAGS)" -o dist/smem_$${os}_$${arch}/smem ./cmd/smem || exit 1; \
	done

clean:
	rm -rf bin dist
