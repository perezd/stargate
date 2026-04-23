# Stargate — bash command classifier for AI coding agents

# Default recipe: build for local platform
default: build

# Derive version from git tags. Validated to prevent shell injection via ldflags.
version := `v=$(git describe --tags --always 2>/dev/null || echo "dev"); if echo "$v" | grep -qE '^[a-zA-Z0-9._-]+$'; then echo "$v"; else echo "ERROR: version '$v' contains invalid characters" >&2; exit 1; fi`

# Build output directory
dist := "dist"

# Install directory (override with: just install INSTALL_DIR=/usr/local/bin)
INSTALL_DIR := `go env GOPATH | cut -d: -f1`+ "/bin"

# Build flags
ldflags := "-X main.Version=" + version
goflags := "CGO_ENABLED=0"

# Build for local platform
build:
    mkdir -p {{dist}}
    {{goflags}} go build -ldflags '{{ldflags}}' -o {{dist}}/stargate ./cmd/stargate/

# Cross-compile for linux/darwin × amd64/arm64
build-all:
    mkdir -p {{dist}}
    {{goflags}} GOOS=linux GOARCH=amd64 go build -ldflags '{{ldflags}}' -o {{dist}}/stargate-linux-amd64 ./cmd/stargate/
    {{goflags}} GOOS=linux GOARCH=arm64 go build -ldflags '{{ldflags}}' -o {{dist}}/stargate-linux-arm64 ./cmd/stargate/
    {{goflags}} GOOS=darwin GOARCH=amd64 go build -ldflags '{{ldflags}}' -o {{dist}}/stargate-darwin-amd64 ./cmd/stargate/
    {{goflags}} GOOS=darwin GOARCH=arm64 go build -ldflags '{{ldflags}}' -o {{dist}}/stargate-darwin-arm64 ./cmd/stargate/

# Run all tests with race detector
test:
    go test ./... -race -count=1

# Run go vet
vet:
    go vet ./...

# Run govulncheck for known vulnerabilities
vuln:
    @which govulncheck > /dev/null 2>&1 || go install golang.org/x/vuln/cmd/govulncheck@v1.1.3
    govulncheck ./...

# Remove build artifacts
clean:
    rm -rf {{dist}}

# Install to INSTALL_DIR (default: $GOPATH/bin). Does NOT use sudo.
install: build
    mkdir -p {{INSTALL_DIR}}
    cp {{dist}}/stargate {{INSTALL_DIR}}/stargate

# Generate SHA256 checksums for all binaries in dist/
checksums: build-all
    cd {{dist}} && if command -v sha256sum > /dev/null 2>&1; then sha256sum stargate-* > SHA256SUMS; elif command -v shasum > /dev/null 2>&1; then shasum -a 256 stargate-* > SHA256SUMS; else echo "ERROR: neither sha256sum nor shasum available" >&2; exit 1; fi
    @echo "Checksums written to {{dist}}/SHA256SUMS"
