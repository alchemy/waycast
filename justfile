# Waycast Justfile
# Run `just --list` to see available commands

CARGO_TARGET_DIR := "target"
CARGO_TARGET := "x86_64-unknown-linux-gnu"
PROJECT_VERSION := `sed -n 's/^version = "\(.*\)"/\1/p' ./Cargo.toml | head -n1`
PKG_BASE_NAME := "waycast-" + PROJECT_VERSION + "-" + CARGO_TARGET

# Show available commands
default:
    just --list

# Display project information
info:
    @echo "Project Version: {{PROJECT_VERSION}}"
    @echo "Target: {{CARGO_TARGET}}"
    @echo "Package Base Name: {{PKG_BASE_NAME}}"
    @echo "Target Dir: {{CARGO_TARGET_DIR}}"

# Build in release mode
build:
    cargo build --release

# Build in debug mode (faster)
build-dev:
    cargo build

# Run all unit tests
test: build
    cargo test --workspace

# Run unit tests only (libraries only)
test-unit:
    cargo test --lib

# Run end-to-end tests (placeholder)
test-e2e: build
    @echo "Running end-to-end tests..."
    # Placeholder for future e2e tests

# Run tests with verbose output
test-verbose: build
    cargo test --workspace -- --nocapture

# Run integration tests (requires real services like GStreamer, PipeWire)
test-integration: build
    cargo test --workspace -- --ignored --nocapture

# Run doc tests
test-doc: build
    cargo test --workspace --doc

# Run all tests including integration
test-all: test test-integration test-e2e

# Run validation suite (protocol compliance + simulation)
test-validation:
    @./scripts/test-validation.sh

# Run mock sink server for testing
mock-sink:
    cargo run --example mock_sink_server

# Format code
fmt:
    cargo fmt

# Check formatting without fixing
fmt-check:
    cargo fmt --check

# Run clippy linter
clippy:
    cargo clippy --workspace -- -D warnings

# Fix clippy issues automatically
clippy-fix:
    cargo clippy --workspace --fix --allow-dirty

# Full lint (format + clippy)
lint: fmt-check clippy

# Fix all linting issues
lint-fix: fmt clippy-fix

# Run pre-commit hooks on all files
pre-commit:
    pre-commit run --all-files

# Install pre-commit hooks
install-hooks:
    pre-commit install

# Run waycast doctor to check system readiness
doctor: build
    ./target/release/waycast doctor

# Run waycast daemon
daemon: build
    ./target/release/waycast daemon

# Run with debug logging
debug *ARGS: build
    RUST_LOG=debug ./target/release/waycast {{ARGS}}

# Run examples
example-doctor: build-dev
    cargo run --example check_system -p waycast-doctor

example-net: build-dev
    cargo run --example discover_and_connect -p waycast-net

example-rtsp: build-dev
    cargo run --example basic_server -p waycast-rtsp

# Install binary to /usr/local/bin
install: build
    sudo cp target/release/waycast /usr/local/bin/
    @echo "Installed waycast to /usr/local/bin/"

# Uninstall binary
uninstall:
    sudo rm -f /usr/local/bin/waycast
    @echo "Uninstalled waycast"

# Clean build artifacts
clean:
    cargo clean

# Deep clean including cargo cache
clean-all:
    cargo clean
    rm -rf target/

# Update dependencies
update:
    cargo update

# Check dependencies for security issues
check-deps:
    cargo audit

# Generate documentation
docs:
    cargo doc --workspace --no-deps --open

# Build release tarball
release-tarball: build
    tar -czf {{PKG_BASE_NAME}}.tar.gz \
        -C target/release waycast
    @echo "Created release tarball: {{PKG_BASE_NAME}}.tar.gz"

# Full release preparation
release: lint test build release-tarball

# Update changelog with version from Cargo.toml
update-changelog:
    git-cliff --config cliff.toml --unreleased --tag v{{PROJECT_VERSION}} -o CHANGELOG.md

# Update version references and Cargo.lock
update-version:
    cargo update --workspace

# Development workflow: lint-fix, test, build
dev: lint-fix test build

# Quick check: fast lint and build (no tests)
check: fmt-check clippy build

# Watch for changes and rebuild
watch:
    cargo watch -x build

# Watch for changes and test
watch-test:
    cargo watch -x test

# Generate cliff.toml if missing
setup-cliff:
    @if [ ! -f cliff.toml ]; then \
        echo "Downloading cliff.toml template..."; \
        curl -sSL https://raw.githubusercontent.com/orhun/git-cliff/main/config.toml -o cliff.toml; \
    fi

# Setup development environment
setup: setup-cliff install-hooks
    @echo "Development environment ready!"
    @echo "Run 'just --list' to see available commands"
