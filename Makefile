.PHONY: test test-cover failfast profile clean format build

PKG=github.com/betterleaks/betterleaks
VERSION := $(shell git fetch --tags 2>/dev/null; git describe --tags --abbrev=0 2>/dev/null || echo "dev")
LDFLAGS=-ldflags "-X=github.com/betterleaks/betterleaks/version.Version=$(VERSION)"
COVER=--cover --coverprofile=cover.out

test-cover:
	go test -v ./... --race $(COVER) $(PKG)
	go tool cover -html=cover.out

format:
	go fmt ./...

test: config/betterleaks.toml format
	go test -v ./... --race $(PKG)

failfast: format
	go test -failfast ./...

build:
	go build $(LDFLAGS) -o betterleaks ./cmd/betterleaks

lint:
	golangci-lint run

clean:
	rm -rf profile
	find . -type f -name '*.got.*' -delete
	find . -type f -name '*.out' -delete

profile: build
	./scripts/profile.sh './betterleaks' '.'

config/betterleaks.toml: $(wildcard cmd/generate/config/**/*)
	go generate ./...
