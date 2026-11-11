.PHONY: test test-cover failfast profile clean format build config

PKG=github.com/betterleaks/betterleaks/v2
VERSION ?= $(shell git describe --tags --match 'v2.*' --always --dirty 2>/dev/null || echo "dev")
LDFLAGS=-ldflags "-X=github.com/betterleaks/betterleaks/v2/version.Version=$(VERSION)"
COVER=--cover --coverprofile=cover.out

test-cover:
	go test -v ./... --race $(COVER) $(PKG)
	go tool cover -html=cover.out

format:
	go fmt ./...

test: config/betterleaks.toml format
	go test -v --race ./... $(PKG)

failfast: format
	go test -failfast ./...

build:
	go build $(LDFLAGS) -o betterleaks .

lint:
	golangci-lint run

clean:
	rm -rf profile
	find . -type f -name '*.got.*' -delete
	find . -type f -name '*.out' -delete

profile: build
	./scripts/profile.sh './betterleaks' '.'

# Test every rule, then regenerate the default config from rules/.
config:
	go test ./rules
	go generate ./rules

config/betterleaks.toml: $(wildcard rules/*.go rules/gen/*)
	go generate ./rules
