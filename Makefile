BIN   := nlnt
CARGO ?= cargo

.PHONY: build release test lint fmt fmt-check clean install deps smoke verify dev

## Build the debug binary.
build:
	$(CARGO) build

## Build the optimized binary.
release: SIGN_TARGET = target/release/$(BIN)
release:
	$(CARGO) build --release
	@$(SIGN)

## Run the (fully offline) test suite.
test:
	$(CARGO) test

## Clippy, warnings are errors.
lint:
	$(CARGO) clippy --all-targets -- -D warnings

fmt:
	$(CARGO) fmt --all

fmt-check:
	$(CARGO) fmt --all -- --check

clean:
	$(CARGO) clean

## Install toolchain components needed by `verify`.
deps:
	rustup component add rustfmt clippy

## Install to ~/.cargo/bin, then re-sign — see the note below.
# `--locked` builds from Cargo.lock, the versions `verify` tested; without it
# `cargo install` re-resolves to the newest semver-compatible crates.
install: SIGN_TARGET = $${CARGO_INSTALL_ROOT:-$$HOME/.cargo}/bin/$(BIN)
install:
	$(CARGO) install --locked --path . --force
	@$(SIGN)

## Debug build, signed, for day-to-day work.
dev: SIGN_TARGET = target/debug/$(BIN)
dev:
	$(CARGO) build
	@$(SIGN)

## Exercise the built binary's offline surface. No network, no keychain.
smoke: build
	@set -e; \
	B=target/debug/$(BIN); \
	$$B --help >/dev/null; \
	$$B info --json >/dev/null; \
	$$B summary --help >/dev/null; \
	$$B loans --help >/dev/null; \
	$$B transactions --help >/dev/null; \
	$$B documents --help >/dev/null; \
	$$B mcp --list-tools >/dev/null; \
	$$B auth --help >/dev/null; \
	$$B auth login --help >/dev/null; \
	$$B config --help >/dev/null; \
	$$B completions bash >/dev/null; \
	echo "smoke ok"

## The CI gate.
verify: fmt-check lint test smoke

# `cargo install` ad-hoc signs the binary, minting a NEW code identity every
# time. macOS scopes keychain "Always Allow" grants to that identity, so each
# reinstall silently revokes the grant and the next run prompts again. Signing
# on `dev` alone is not enough — install and release must sign too.
# The identity is created once by cli-common/scripts/setup-dev-signing.sh.
define SIGN
if [ -x "$$HOME/Dev/cli-common/scripts/dev-sign.sh" ]; then \
	"$$HOME/Dev/cli-common/scripts/dev-sign.sh" $(SIGN_TARGET); \
else echo "cli-common/scripts/dev-sign.sh not found — $(SIGN_TARGET) left ad-hoc signed"; fi
endef
